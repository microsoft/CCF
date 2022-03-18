# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import time
from enum import Enum, auto
import paramiko
import subprocess
from contextlib import contextmanager
import infra.path
import ctypes
import signal
import re
import stat
import shutil
from collections import deque
from jinja2 import Environment, FileSystemLoader, select_autoescape
import json

from loguru import logger as LOG

DBG = os.getenv("DBG", "cgdb")
FILE_TIMEOUT = 60

_libc = ctypes.CDLL("libc.so.6")


def _term_on_pdeathsig():
    # usr/include/linux/prctl.h: #define PR_SET_PDEATHSIG 1
    _libc.prctl(1, signal.SIGTERM)


def popen(*args, **kwargs):
    kwargs["preexec_fn"] = _term_on_pdeathsig
    return subprocess.Popen(*args, **kwargs)


@contextmanager
def sftp_session(hostname):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname)
    try:
        session = client.open_sftp()
        try:
            yield session
        finally:
            session.close()
    finally:
        client.close()


DEFAULT_TAIL_LINES_LEN = 10


def log_errors(
    out_path,
    err_path,
    tail_lines_len=DEFAULT_TAIL_LINES_LEN,
    ignore_error_patterns=None,
):
    error_filter = ["[fail ]", "[fatal]", "Atom leak", "atom leakage"]
    error_lines = []
    try:
        tail_lines = deque(maxlen=tail_lines_len)
        with open(out_path, "r", errors="replace", encoding="utf-8") as lines:
            for line in lines:
                stripped_line = line.rstrip()
                tail_lines.append(stripped_line)
                if any(x in stripped_line for x in error_filter):
                    ignore = False
                    if ignore_error_patterns is not None:
                        for pattern in ignore_error_patterns:
                            if pattern in stripped_line:
                                ignore = True
                                break
                    if not ignore:
                        LOG.error("{}: {}".format(out_path, stripped_line))
                        error_lines.append(stripped_line)
        if error_lines:
            LOG.info(
                "{} errors found, printing end of output for context:", len(error_lines)
            )
            for line in tail_lines:
                LOG.info(line)
    except IOError:
        LOG.exception("Could not check output {} for errors".format(out_path))

    fatal_error_lines = []
    try:
        with open(err_path, "r", errors="replace", encoding="utf-8") as lines:
            fatal_error_lines = [
                line
                for line in lines.readlines()
                if not line.startswith("[get_qpl_handle ")
            ]
            if fatal_error_lines:
                LOG.error(f"Contents of {err_path}:\n{''.join(fatal_error_lines)}")
    except IOError:
        LOG.exception("Could not read err output {}".format(err_path))

    # See https://github.com/microsoft/CCF/issues/1701
    ignore_fatal_errors = False
    for line in fatal_error_lines:
        if line.startswith("Tracer caught signal 11"):
            ignore_fatal_errors = True
    if ignore_fatal_errors:
        fatal_error_lines = []

    return error_lines, fatal_error_lines


class CmdMixin(object):
    def set_perf(self):
        self.cmd = [
            "perf",
            "record",
            "--freq=1000",
            "--call-graph=dwarf",
            "-s",
        ] + self.cmd

    def _get_perf(self, lines):
        pattern = "=> (.*)tx/s"
        for line in lines:
            LOG.debug(line.decode())
            res = re.search(pattern, line.decode())
            if res:
                return float(res.group(1))
        raise ValueError(f"No performance result found (pattern is {pattern})")


class SSHRemote(CmdMixin):
    def __init__(
        self,
        name,
        hostname,
        exe_files,
        data_files,
        cmd,
        workspace,
        common_dir,
        env=None,
    ):
        """
        Runs a command on a remote host, through an SSH connection. A temporary
        directory is created, and some files can be shipped over. The command is
        run out of that directory.

        Note that the name matters, since the temporary directory that will be first
        deleted, then created and populated is workspace/name. There is deliberately no
        cleanup on shutdown, to make debugging/inspection possible.

        setup() connects, creates the directory and ships over the files
        start() runs the specified command
        stop()  disconnects, which shuts down the command via SIGHUP
        """
        self.hostname = hostname
        self.exe_files = exe_files
        self.data_files = data_files
        self.cmd = cmd
        self.client = paramiko.SSHClient()
        # this client (proc_client) is used to execute commands on the remote host since the main client uses pty
        self.proc_client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.proc_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.common_dir = common_dir
        self.root = os.path.join(workspace, name)
        self.name = name
        self.env = env or {}
        self.out = os.path.join(self.root, "out")
        self.err = os.path.join(self.root, "err")
        self.suspension_proc = None
        self.pid_file = f"{os.path.basename(self.cmd[0])}.pid"
        self._pid = None

    def _rc(self, cmd):
        LOG.info("[{}] {}".format(self.hostname, cmd))
        _, stdout, _ = self.client.exec_command(cmd)
        return stdout.channel.recv_exit_status()

    def _connect(self):
        LOG.debug("[{}] connect".format(self.hostname))
        self.client.connect(self.hostname)
        self.proc_client.connect(self.hostname)

    def _setup_files(self):
        assert self._rc("rm -rf {}".format(self.root)) == 0
        assert self._rc("mkdir -p {}".format(self.root)) == 0
        # For SSHRemote, both executable files (host and enclave) and data
        # files (ledger, secrets) are copied to the remote
        session = self.client.open_sftp()
        for path in self.exe_files:
            tgt_path = os.path.join(self.root, os.path.basename(path))
            LOG.info("[{}] copy {} from {}".format(self.hostname, tgt_path, path))
            session.put(path, tgt_path)
            stat = os.stat(path)
            session.chmod(tgt_path, stat.st_mode)
        for path in self.data_files:
            tgt_path = os.path.join(self.root, os.path.basename(path))
            if os.path.isdir(path):
                session.mkdir(tgt_path)
                for f in os.listdir(path):
                    session.put(os.path.join(path, f), os.path.join(tgt_path, f))
            else:
                session.put(path, tgt_path)
            LOG.info("[{}] copy {} from {}".format(self.hostname, tgt_path, path))
        session.close()

    def get(
        self,
        file_name,
        dst_path,
        timeout=FILE_TIMEOUT,
        target_name=None,
        pre_condition_func=lambda src_dir, _: True,
    ):
        """
        Get file called `file_name` under the root of the remote. If the
        file is missing, wait for timeout, and raise an exception.

        If the file is present, it is copied to the CWD on the caller's
        host, as `target_name` if it is set.

        This call spins up a separate client because we don't want to interrupt
        the main cmd that may be running.
        """
        with sftp_session(self.hostname) as session:
            end_time = time.time() + timeout
            start_time = time.time()
            while time.time() < end_time:
                try:
                    target_name = target_name or file_name
                    fileattr = session.lstat(os.path.join(self.root, file_name))
                    if stat.S_ISDIR(fileattr.st_mode):
                        src_dir = os.path.join(self.root, file_name)
                        dst_dir = os.path.join(dst_path, file_name)
                        if os.path.exists(dst_dir):
                            shutil.rmtree(dst_dir)
                        os.makedirs(dst_dir)
                        if not pre_condition_func(src_dir, session.listdir):
                            raise RuntimeError(
                                "Pre-condition for getting remote files failed"
                            )
                        for f in session.listdir(src_dir):
                            session.get(
                                os.path.join(src_dir, f), os.path.join(dst_dir, f)
                            )
                    else:
                        session.get(
                            os.path.join(self.root, file_name),
                            os.path.join(dst_path, target_name),
                        )
                    LOG.debug(
                        "[{}] found {} after {}s".format(
                            self.hostname, file_name, int(time.time() - start_time)
                        )
                    )
                    break
                except FileNotFoundError:
                    time.sleep(0.1)
            else:
                raise ValueError(file_name)

    def list_files(self, timeout=FILE_TIMEOUT):
        files = []
        with sftp_session(self.hostname) as session:
            end_time = time.time() + timeout
            while time.time() < end_time:
                try:
                    files = session.listdir(self.root)

                    break
                except Exception:
                    time.sleep(0.1)

            else:
                raise ValueError(self.root)
        return files

    def get_logs(
        self, tail_lines_len=DEFAULT_TAIL_LINES_LEN, ignore_error_patterns=None
    ):
        with sftp_session(self.hostname) as session:
            for filepath in (self.err, self.out):
                try:
                    local_file_name = "{}_{}_{}".format(
                        self.hostname, self.name, os.path.basename(filepath)
                    )
                    dst_path = os.path.join(self.common_dir, local_file_name)
                    session.get(filepath, dst_path)
                    LOG.info("Downloaded {}".format(dst_path))
                except FileNotFoundError:
                    LOG.warning(
                        "Failed to download {} to {} (host: {})".format(
                            filepath, dst_path, self.hostname
                        )
                    )
        return log_errors(
            os.path.join(self.common_dir, "{}_{}_out".format(self.hostname, self.name)),
            os.path.join(self.common_dir, "{}_{}_err".format(self.hostname, self.name)),
            tail_lines_len=tail_lines_len,
            ignore_error_patterns=ignore_error_patterns,
        )

    def start(self):
        """
        Start cmd on the remote host. stdout and err are captured to file locally.

        We create a pty on the remote host under which to run the command, so as to
        get a SIGHUP on disconnection.
        """
        cmd = self.get_cmd()
        LOG.info("[{}] {}".format(self.hostname, cmd))
        self.client.exec_command(cmd, get_pty=True)
        self.pid()

    def pid(self):
        if self._pid is None:
            pid_path = os.path.join(self.root, self.pid_file)
            time_left = 3
            while time_left > 0:
                _, stdout, _ = self.proc_client.exec_command(f'cat "{pid_path}"')
                res = stdout.read().strip()
                if res:
                    self._pid = int(res)
                    break
                time_left = max(time_left - 0.1, 0)
                if not time_left:
                    raise TimeoutError("Failed to read PID from file")
                time.sleep(0.1)
        return self._pid

    def suspend(self):
        _, stdout, _ = self.proc_client.exec_command(f"kill -STOP {self.pid()}")
        if stdout.channel.recv_exit_status() != 0:
            raise RuntimeError(f"Remote {self.name} could not be suspended")

    def resume(self):
        _, stdout, _ = self.proc_client.exec_command(f"kill -CONT {self.pid()}")
        if stdout.channel.recv_exit_status() != 0:
            raise RuntimeError(f"Could not resume remote {self.name} from suspension!")

    def stop(self, ignore_error_patterns=None):
        """
        Disconnect the client, and therefore shut down the command as well.
        """
        LOG.info("[{}] closing".format(self.hostname))
        (
            errors,
            fatal_errors,
        ) = self.get_logs(ignore_error_patterns=ignore_error_patterns)
        self.client.close()
        self.proc_client.close()
        return errors, fatal_errors

    def setup(self):
        """
        Connect to the remote host, empty the temporary directory if it exsits,
        and populate it with the initial set of files.
        """
        self._connect()
        self._setup_files()

    def get_cmd(self):
        env = " ".join(f"{key}={value}" for key, value in self.env.items())
        cmd = " ".join(self.cmd)
        return f"cd {self.root} && {env} {cmd} 1> {self.out} 2> {self.err} 0< /dev/null"

    def debug_node_cmd(self):
        cmd = " ".join(self.cmd)
        return f"cd {self.root} && {DBG} --args {cmd}"

    def _connect_new(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.hostname)
        return client

    def check_done(self):
        client = self._connect_new()
        try:
            _, stdout, _ = client.exec_command(f"ps -p {self.pid()}")
            return stdout.channel.recv_exit_status() == 1
        finally:
            client.close()

    def get_result(self, line_count):
        client = self._connect_new()
        try:
            _, stdout, _ = client.exec_command(f"tail -{line_count} {self.out}")
            if stdout.channel.recv_exit_status() == 0:
                lines = stdout.read().splitlines()
                result = lines[-line_count:]
                return self._get_perf(result)
        finally:
            client.close()


class LocalRemote(CmdMixin):
    def __init__(
        self,
        name,
        hostname,
        exe_files,
        data_files,
        cmd,
        workspace,
        common_dir,
        env=None,
    ):
        """
        Local Equivalent to the SSHRemote
        """
        self.hostname = hostname
        self.exe_files = exe_files
        self.data_files = data_files
        self.cmd = cmd
        self.root = os.path.join(workspace, name)
        self.common_dir = common_dir
        self.proc = None
        self.stdout = None
        self.stderr = None
        self.env = env
        self.name = name
        self.out = os.path.join(self.root, "out")
        self.err = os.path.join(self.root, "err")

    def _rc(self, cmd):
        LOG.info("[{}] {}".format(self.hostname, cmd))
        return subprocess.call(cmd, shell=True)

    def cp(self, src_path, dst_path):
        if os.path.isdir(src_path):
            assert self._rc("rm -rf {}".format(os.path.join(dst_path))) == 0
            assert self._rc("cp -r {} {}".format(src_path, dst_path)) == 0
        else:
            assert self._rc("cp {} {}".format(src_path, dst_path)) == 0

    def _setup_files(self):
        assert self._rc("rm -rf {}".format(self.root)) == 0
        assert self._rc("mkdir -p {}".format(self.root)) == 0
        for path in self.exe_files:
            dst_path = os.path.normpath(os.path.join(self.root, os.path.basename(path)))
            src_path = os.path.normpath(os.path.join(os.getcwd(), path))
            assert self._rc("ln -s {} {}".format(src_path, dst_path)) == 0
        for path in self.data_files:
            dst_path = os.path.join(self.root, os.path.basename(path))
            self.cp(path, dst_path)

    def get(
        self,
        src_path,
        dst_path,
        timeout=FILE_TIMEOUT,
        target_name=None,
        pre_condition_func=lambda src_dir, _: True,
    ):
        path = os.path.join(self.root, src_path)
        end_time = time.time() + timeout
        while time.time() < end_time:
            if os.path.exists(path):
                break
            time.sleep(0.1)
        else:
            raise ValueError(path)
        if not pre_condition_func(path, os.listdir):
            raise RuntimeError("Pre-condition for getting remote files failed")
        target_name = target_name or os.path.basename(src_path)
        self.cp(path, os.path.join(dst_path, target_name))

    def list_files(self):
        return os.listdir(self.root)

    def start(self):
        """
        Start cmd. stdout and err are captured to file locally.
        """
        cmd = self.get_cmd()
        LOG.info(f"[{self.hostname}] {cmd} (env: {self.env})")
        self.stdout = open(self.out, "wb")
        self.stderr = open(self.err, "wb")
        self.proc = popen(
            self.cmd,
            cwd=self.root,
            stdout=self.stdout,
            stderr=self.stderr,
            env=self.env,
        )

    def suspend(self):
        self.proc.send_signal(signal.SIGSTOP)

    def resume(self):
        self.proc.send_signal(signal.SIGCONT)

    def get_logs(
        self, tail_lines_len=DEFAULT_TAIL_LINES_LEN, ignore_error_patterns=None
    ):
        return log_errors(
            self.out,
            self.err,
            tail_lines_len=tail_lines_len,
            ignore_error_patterns=ignore_error_patterns,
        )

    def stop(self, ignore_error_patterns=None):
        """
        Disconnect the client, and therefore shut down the command as well.
        """
        LOG.info("[{}] closing".format(self.hostname))
        if self.proc:
            self.proc.terminate()
            self.proc.wait(10)
            exit_code = self.proc.returncode
            if exit_code is not None and exit_code < 0:
                signal_str = signal.strsignal(-exit_code)
                LOG.error(f"{self.hostname} exited with signal: {signal_str}")
            if self.stdout:
                self.stdout.close()
            if self.stderr:
                self.stderr.close()
            return self.get_logs(ignore_error_patterns=ignore_error_patterns)

    def setup(self):
        """
        Empty the temporary directory if it exists,
        and populate it with the initial set of files.
        """
        self._setup_files()

    def get_cmd(self, include_dir=True):
        cmd = f"cd {self.root} && " if include_dir else ""
        cmd += f'{" ".join(self.cmd)} 1> {self.out} 2> {self.err}'
        return cmd

    def debug_node_cmd(self):
        cmd = " ".join(self.cmd)
        return f"cd {self.root} && {DBG} --args {cmd}"

    def check_done(self):
        return self.proc.poll() is not None

    def get_result(self, line_count):
        with open(self.out, "rb") as out:
            lines = out.read().splitlines()
            result = lines[-line_count:]
            return self._get_perf(result)


CCF_TO_OE_LOG_LEVEL = {
    "trace": "VERBOSE",
    "debug": "INFO",
    "info": "WARNING",
    "fail": "ERROR",
    "fatal": "FATAL",
}


class CCFRemote(object):
    BIN = "cchost"
    TEMPLATE_CONFIGURATION_FILE = "config.jinja"
    DEPS = []

    def __init__(
        self,
        start_type,
        enclave_file,
        enclave_type,
        remote_class,
        workspace,
        common_dir,
        label="",
        binary_dir=".",
        local_node_id=None,
        host=None,
        ledger_dir=None,
        read_only_ledger_dirs=None,
        snapshots_dir=None,
        common_read_only_ledger_dir=None,
        constitution=None,
        curve_id=None,
        version=None,
        host_log_level="Info",
        major_version=None,
        include_addresses=True,
        config_file=None,
        join_timer_s=None,
        sig_ms_interval=None,
        jwt_key_refresh_interval_s=None,
        election_timeout_ms=None,
        node_data_json_file=None,
        **kwargs,
    ):
        """
        Run a ccf binary on a remote host.
        """

        self.name = f"{label}_{local_node_id}"
        self.start_type = start_type
        self.local_node_id = local_node_id
        self.pem = f"{local_node_id}.pem"
        self.node_address_file = f"{local_node_id}.node_address"
        self.rpc_addresses_file = f"{local_node_id}.rpc_addresses"

        # 1.x releases have a separate cchost.virtual binary for virtual enclaves
        if enclave_type == "virtual" and (
            (major_version is not None and major_version <= 1)
            # This is still present in 2.0.0-rc0
            or (version == "ccf-2.0.0-rc0")
        ):
            self.BIN = "cchost.virtual"
        self.BIN = infra.path.build_bin_path(self.BIN, binary_dir=binary_dir)
        self.common_dir = common_dir
        self.pub_host = host.get_primary_interface().public_host
        self.enclave_file = os.path.join(".", os.path.basename(enclave_file))
        data_files = []
        exe_files = []

        # Main ledger directory
        self.ledger_dir = os.path.normpath(ledger_dir) if ledger_dir else None
        self.ledger_dir_name = (
            os.path.basename(self.ledger_dir)
            if self.ledger_dir
            else f"{local_node_id}.ledger"
        )

        # Read-only ledger directories
        self.read_only_ledger_dirs = read_only_ledger_dirs or []
        self.read_only_ledger_dirs_names = []
        for d in self.read_only_ledger_dirs:
            self.read_only_ledger_dirs_names.append(os.path.basename(d))
        if common_read_only_ledger_dir is not None:
            self.read_only_ledger_dirs_names.append(common_read_only_ledger_dir)

        # Snapshots
        self.snapshots_dir = os.path.normpath(snapshots_dir) if snapshots_dir else None
        self.snapshot_dir_name = (
            os.path.basename(self.snapshots_dir)
            if self.snapshots_dir
            else f"{local_node_id}.snapshots"
        )

        # Constitution
        constitution = [
            os.path.join(self.common_dir, os.path.basename(f)) for f in constitution
        ]

        # Configuration file
        if config_file:
            LOG.info(
                f"Node {self.local_node_id}: Using configuration file {config_file}"
            )
            with open(config_file, encoding="utf-8") as f:
                config = json.load(f)
            self.pem = config.get("node_certificate_file", "nodecert.pem")
            self.node_address_file = config.get("node_address_file")
            self.rpc_addresses_file = config.get("rpc_addresses_file")

        elif major_version is None or major_version > 1:
            loader = FileSystemLoader(binary_dir)
            env = Environment(loader=loader, autoescape=select_autoescape())
            t = env.get_template(self.TEMPLATE_CONFIGURATION_FILE)
            output = t.render(
                start_type=start_type.name.title(),
                enclave_file=self.enclave_file,
                enclave_type=enclave_type.title(),
                rpc_interfaces=infra.interfaces.HostSpec.to_json(host),
                node_certificate_file=self.pem,
                node_address_file=self.node_address_file,
                rpc_addresses_file=self.rpc_addresses_file,
                ledger_dir=self.ledger_dir_name,
                read_only_ledger_dirs=self.read_only_ledger_dirs_names,
                snapshots_dir=self.snapshot_dir_name,
                constitution=constitution,
                curve_id=curve_id.name.title(),
                host_log_level=host_log_level.title(),
                join_timer=f"{join_timer_s}s" if join_timer_s else None,
                signature_interval_duration=f"{sig_ms_interval}ms",
                jwt_key_refresh_interval=f"{jwt_key_refresh_interval_s}s",
                election_timeout=f"{election_timeout_ms}ms",
                node_data_json_file=node_data_json_file,
                **kwargs,
            )

            config_file_name = f"{self.local_node_id}.config.json"
            config_file = os.path.join(common_dir, config_file_name)
            exe_files += [config_file]

            with open(config_file, "w", encoding="utf-8") as f:
                f.write(output)

        exe_files += [self.BIN, enclave_file] + self.DEPS
        data_files += [self.ledger_dir] if self.ledger_dir else []
        data_files += [self.snapshots_dir] if self.snapshots_dir else []
        if self.read_only_ledger_dirs_names:
            data_files.extend(
                [os.path.join(self.common_dir, f) for f in self.read_only_ledger_dirs]
            )

        # exe_files may be relative or absolute. The remote implementation should
        # copy (or symlink) to the target workspace, and then node will be able
        # to reference the destination file locally in the target workspace.
        bin_path = os.path.join(".", os.path.basename(self.BIN))

        if major_version is None or major_version > 1:
            cmd = [bin_path, "--config", config_file]
            if start_type == StartType.join:
                data_files += [os.path.join(self.common_dir, "service_cert.pem")]

        else:
            consensus = kwargs.get("consensus")
            node_address = kwargs.get("node_address")
            worker_threads = kwargs.get("worker_threads")
            ledger_chunk_bytes = kwargs.get("ledger_chunk_bytes")
            subject_alt_names = kwargs.get("subject_alt_names")
            snapshot_tx_interval = kwargs.get("snapshot_tx_interval")
            max_open_sessions = kwargs.get("max_open_sessions")
            max_open_sessions_hard = kwargs.get("max_open_sessions_hard")
            initial_node_cert_validity_days = kwargs.get(
                "initial_node_cert_validity_days"
            )
            node_client_host = kwargs.get("node_client_host")
            members_info = kwargs.get("members_info")
            target_rpc_address = kwargs.get("target_rpc_address")
            maximum_node_certificate_validity_days = kwargs.get(
                "maximum_node_certificate_validity_days"
            )
            reconfiguration_type = kwargs.get("reconfiguration_type")
            log_format_json = kwargs.get("log_format_json")
            sig_tx_interval = kwargs.get("sig_tx_interval")

            primary_rpc_interface = host.get_primary_interface()
            cmd = [
                bin_path,
                f"--enclave-file={self.enclave_file}",
                f"--enclave-type={enclave_type}",
                f"--node-address-file={self.node_address_file}",
                f"--rpc-address={infra.interfaces.make_address(primary_rpc_interface.host, primary_rpc_interface.port)}",
                f"--rpc-address-file={self.rpc_addresses_file}",
                f"--ledger-dir={self.ledger_dir_name}",
                f"--snapshot-dir={self.snapshot_dir_name}",
                f"--node-cert-file={self.pem}",
                f"--host-log-level={host_log_level}",
                f"--raft-election-timeout-ms={election_timeout_ms}",
                f"--consensus={consensus}",
                f"--worker-threads={worker_threads}",
            ]

            if include_addresses:
                cmd += [
                    f"--node-address={node_address}",
                    f"--public-rpc-address={infra.interfaces.make_address(primary_rpc_interface.public_host, primary_rpc_interface.public_port)}",
                ]

            if log_format_json:
                cmd += ["--log-format-json"]

            if sig_tx_interval:
                cmd += [f"--sig-tx-interval={sig_tx_interval}"]

            if sig_ms_interval:
                cmd += [f"--sig-ms-interval={sig_ms_interval}"]

            if ledger_chunk_bytes:
                cmd += [f"--ledger-chunk-bytes={ledger_chunk_bytes}"]

            if subject_alt_names:
                cmd += [f"--san={s}" for s in subject_alt_names]

            if snapshot_tx_interval:
                cmd += [f"--snapshot-tx-interval={snapshot_tx_interval}"]

            if max_open_sessions:
                cmd += [f"--max-open-sessions={max_open_sessions}"]

            if jwt_key_refresh_interval_s:
                cmd += [f"--jwt-key-refresh-interval-s={jwt_key_refresh_interval_s}"]

            for f in self.read_only_ledger_dirs_names:
                cmd += [f"--read-only-ledger-dir={f}"]

            for f in self.read_only_ledger_dirs:
                data_files += [os.path.join(self.common_dir, f)]

            if curve_id is not None:
                cmd += [f"--curve-id={curve_id.name}"]

            # Added in 1.x
            if not major_version or major_version > 1:
                if initial_node_cert_validity_days:
                    cmd += [
                        f"--initial-node-cert-validity-days={initial_node_cert_validity_days}"
                    ]

                if node_client_host:
                    cmd += [f"--node-client-interface={node_client_host}"]

                if reconfiguration_type and reconfiguration_type != "OneTransaction":
                    cmd += [f"--reconfiguration-type={reconfiguration_type}"]

                if max_open_sessions_hard:
                    cmd += [f"--max-open-sessions-hard={max_open_sessions_hard}"]

            if start_type == StartType.start:
                cmd += ["start", "--network-cert-file=service_cert.pem"]
                for fragment in constitution:
                    cmd.append(f"--constitution={os.path.basename(fragment)}")
                    data_files += [
                        os.path.join(self.common_dir, os.path.basename(fragment))
                    ]

                if members_info is None:
                    raise ValueError(
                        "Starting node should be given at least one member info"
                    )
                for mi in members_info:
                    member_info_cmd = f'--member-info={mi["certificate_file"]}'
                    data_files.append(mi["certificate_file"])
                    if mi["encryption_public_key_file"] is not None:
                        member_info_cmd += f',{mi["encryption_public_key_file"]}'
                        data_files.append(mi["encryption_public_key_file"])
                    elif mi["data_json_file"] is not None:
                        member_info_cmd += ","
                    if mi["data_json_file"] is not None:
                        member_info_cmd += f',{mi["data_json_file"]}'
                        data_files.append(mi["data_json_file"])
                    cmd += [member_info_cmd]

                # Added in 1.x
                if not major_version or major_version > 1:
                    if maximum_node_certificate_validity_days:
                        cmd += [
                            f"--max-allowed-node-cert-validity-days={maximum_node_certificate_validity_days}"
                        ]

            elif start_type == StartType.join:
                cmd += [
                    "join",
                    "--network-cert-file=service_cert.pem",
                    f"--target-rpc-address={target_rpc_address}",
                    f"--join-timer={join_timer_s * 1000}",
                ]
                data_files += [os.path.join(self.common_dir, "service_cert.pem")]

            elif start_type == StartType.recover:
                cmd += ["recover", "--network-cert-file=service_cert.pem"]

            else:
                raise ValueError(
                    f"Unexpected CCFRemote start type {start_type}. Should be start, join or recover"
                )

        env = {}
        if enclave_type == "virtual":
            env["UBSAN_OPTIONS"] = "print_stacktrace=1"
            ubsan_opts = kwargs.get("ubsan_options")
            if ubsan_opts:
                env["UBSAN_OPTIONS"] += ":" + ubsan_opts

        oe_log_level = CCF_TO_OE_LOG_LEVEL.get(kwargs.get("host_log_level"))
        if oe_log_level:
            env["OE_LOG_LEVEL"] = oe_log_level

        self.remote = remote_class(
            self.name,
            self.pub_host,
            exe_files,
            data_files,
            cmd,
            workspace,
            common_dir,
            env,
        )

    def setup(self):
        self.remote.setup()

    def start(self):
        self.remote.start()

    def suspend(self):
        return self.remote.suspend()

    def resume(self):
        self.remote.resume()

    def get_startup_files(self, dst_path, timeout=FILE_TIMEOUT):
        self.remote.get(self.pem, dst_path, timeout=timeout)
        if self.node_address_file is not None:
            self.remote.get(self.node_address_file, dst_path, timeout=timeout)
        if self.rpc_addresses_file is not None:
            self.remote.get(self.rpc_addresses_file, dst_path, timeout=timeout)
        if self.start_type in {StartType.start, StartType.recover}:
            self.remote.get("service_cert.pem", dst_path, timeout=timeout)

    def debug_node_cmd(self):
        return self.remote.debug_node_cmd()

    def stop(self, *args, **kwargs):
        errors, fatal_errors = [], []
        try:
            errors, fatal_errors = self.remote.stop(*args, **kwargs)
        except Exception:
            LOG.exception("Failed to shut down {} cleanly".format(self.local_node_id))
        return errors, fatal_errors

    def check_done(self):
        return self.remote.check_done()

    def set_perf(self):
        self.remote.set_perf()

    def get_ledger(self, ledger_dir_name):
        self.remote.get(
            self.ledger_dir_name, self.common_dir, target_name=ledger_dir_name
        )
        read_only_ledger_dirs = []
        for read_only_ledger_dir in self.read_only_ledger_dirs:
            name = f"{read_only_ledger_dir}.ro"
            self.remote.get(
                os.path.basename(read_only_ledger_dir),
                self.common_dir,
                target_name=name,
            )
            read_only_ledger_dirs.append(os.path.join(self.common_dir, name))
        return (os.path.join(self.common_dir, ledger_dir_name), read_only_ledger_dirs)

    def get_snapshots(self):
        self.remote.get(self.snapshot_dir_name, self.common_dir)
        return os.path.join(self.common_dir, self.snapshot_dir_name)

    def get_committed_snapshots(self, pre_condition_func=lambda src_dir, _: True):
        self.remote.get(
            self.snapshot_dir_name,
            self.common_dir,
            pre_condition_func=pre_condition_func,
        )
        return os.path.join(self.common_dir, self.snapshot_dir_name)

    def log_path(self):
        return self.remote.out

    def ledger_paths(self):
        paths = [os.path.join(self.remote.root, self.ledger_dir_name)]
        for read_only_ledger_dir_name in self.read_only_ledger_dirs_names:
            paths += [os.path.join(self.remote.root, read_only_ledger_dir_name)]
        return paths

    def get_logs(
        self, tail_lines_len=DEFAULT_TAIL_LINES_LEN, ignore_error_patterns=None
    ):
        return self.remote.get_logs(
            tail_lines_len=tail_lines_len, ignore_error_patterns=ignore_error_patterns
        )

    def get_host(self):
        return self.pub_host


class StartType(Enum):
    start = auto()
    join = auto()
    recover = auto()
