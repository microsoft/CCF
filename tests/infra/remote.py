# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import time
from enum import Enum
import paramiko
import subprocess
from contextlib import contextmanager
import infra.path
import uuid
import ctypes
import signal
import re
import stat
import shutil
from collections import deque

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


def coverage_enabled(binary):
    return (
        subprocess.run(
            f"nm -C {binary} | grep __llvm_coverage_mapping", shell=True, check=False
        ).returncode
        == 0
    )


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


def log_errors(out_path, err_path):
    error_filter = ["[fail ]", "[fatal]"]
    error_lines = []
    try:
        tail_lines = deque(maxlen=10)
        with open(out_path, "r", errors="replace") as lines:
            for line in lines:
                stripped_line = line.rstrip()
                tail_lines.append(stripped_line)
                if any(x in stripped_line for x in error_filter):
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
        with open(err_path, "r", errors="replace") as lines:
            fatal_error_lines = lines.readlines()
            if fatal_error_lines:
                LOG.error(f"Contents of {err_path}:\n{''.join(fatal_error_lines)}")
    except IOError:
        LOG.exception("Could not read err output {}".format(err_path))

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
        label,
        common_dir,
        env=None,
        log_format_json=None,
    ):
        """
        Runs a command on a remote host, through an SSH connection. A temporary
        directory is created, and some files can be shipped over. The command is
        run out of that directory.

        Note that the name matters, since the temporary directory that will be first
        deleted, then created and populated is workspace/label_name. There is deliberately no
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
        self.root = os.path.join(workspace, label + "_" + name)
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
                                os.path.join(src_dir, f),
                                os.path.join(dst_dir, f),
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

    def get_logs(self):
        with sftp_session(self.hostname) as session:
            for filepath in (self.err, self.out):
                try:
                    local_file_name = "{}_{}_{}".format(
                        self.hostname,
                        self.name,
                        os.path.basename(filepath),
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

    def stop(self):
        """
        Disconnect the client, and therefore shut down the command as well.
        """
        LOG.info("[{}] closing".format(self.hostname))
        self.get_logs()
        errors, fatal_errors = log_errors(
            os.path.join(self.common_dir, "{}_{}_out".format(self.hostname, self.name)),
            os.path.join(self.common_dir, "{}_{}_err".format(self.hostname, self.name)),
        )
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


@contextmanager
def ssh_remote(*args, **kwargs):
    """
    Context Manager wrapper for SSHRemote
    """
    remote = SSHRemote(*args, **kwargs)
    try:
        remote.setup()
        remote.start()
        yield remote
    finally:
        remote.stop()


class LocalRemote(CmdMixin):
    def __init__(
        self,
        name,
        hostname,
        exe_files,
        data_files,
        cmd,
        workspace,
        label,
        common_dir,
        env=None,
        log_format_json=None,
    ):
        """
        Local Equivalent to the SSHRemote
        """
        self.hostname = hostname
        self.exe_files = exe_files
        self.data_files = data_files
        self.cmd = cmd
        self.root = os.path.join(workspace, label + "_" + name)
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

    def _cp(self, src_path, dst_path):
        if os.path.isdir(src_path):
            assert (
                self._rc(
                    "rm -rf {}".format(
                        os.path.join(dst_path, os.path.basename(src_path))
                    )
                )
                == 0
            )
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
            self._cp(path, dst_path)

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
        if target_name is not None:
            self._cp(path, os.path.join(dst_path, target_name))
        else:
            self._cp(path, dst_path)

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

    def stop(self):
        """
        Disconnect the client, and therefore shut down the command as well.
        """
        LOG.info("[{}] closing".format(self.hostname))
        if self.proc:
            self.proc.terminate()
            self.proc.wait(10)
            if self.stdout:
                self.stdout.close()
            if self.stderr:
                self.stderr.close()
            return log_errors(self.out, self.err)

    def setup(self):
        """
        Empty the temporary directory if it exists,
        and populate it with the initial set of files.
        """
        self._setup_files()

    def get_cmd(self):
        cmd = " ".join(self.cmd)
        return f"cd {self.root} && {cmd} 1> {self.out} 2> {self.err}"

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


def make_address(host, port=None):
    if port is not None:
        return f"{host}:{port}"
    return host


class CCFRemote(object):
    BIN = "cchost"
    DEPS = []

    def __init__(
        self,
        start_type,
        lib_path,
        local_node_id,
        host,
        pubhost,
        node_port,
        rpc_port,
        remote_class,
        enclave_type,
        workspace,
        label,
        common_dir,
        target_rpc_address=None,
        members_info=None,
        snapshot_dir=None,
        join_timer=None,
        host_log_level="info",
        sig_tx_interval=5000,
        sig_ms_interval=1000,
        raft_election_timeout=1000,
        pbft_view_change_timeout=5000,
        consensus="cft",
        worker_threads=0,
        memory_reserve_startup=0,
        gov_script=None,
        ledger_dir=None,
        log_format_json=None,
        binary_dir=".",
        ledger_chunk_bytes=(5 * 1000 * 1000),
        domain=None,
        snapshot_tx_interval=None,
    ):
        """
        Run a ccf binary on a remote host.
        """
        self.start_type = start_type
        self.local_node_id = local_node_id
        self.pem = f"{local_node_id}.pem"
        self.node_address_path = f"{local_node_id}.node_address"
        self.rpc_address_path = f"{local_node_id}.rpc_address"
        self.BIN = infra.path.build_bin_path(
            self.BIN, enclave_type, binary_dir=binary_dir
        )

        self.ledger_dir = os.path.normpath(ledger_dir) if ledger_dir else None
        self.ledger_dir_name = (
            os.path.basename(self.ledger_dir)
            if self.ledger_dir
            else f"{local_node_id}.ledger"
        )
        self.snapshot_dir = os.path.normpath(snapshot_dir) if snapshot_dir else None
        self.snapshot_dir_name = (
            os.path.basename(self.snapshot_dir) if self.snapshot_dir else "snapshots"
        )

        self.common_dir = common_dir

        exe_files = [self.BIN, lib_path] + self.DEPS
        data_files = [self.ledger_dir] if self.ledger_dir else []
        data_files += [self.snapshot_dir] if self.snapshot_dir else []

        # exe_files may be relative or absolute. The remote implementation should
        # copy (or symlink) to the target workspace, and then node will be able
        # to reference the destination file locally in the target workspace.
        bin_path = os.path.join(".", os.path.basename(self.BIN))
        enclave_path = os.path.join(".", os.path.basename(lib_path))

        election_timeout_arg = (
            f"--pbft_view-change-timeout-ms={pbft_view_change_timeout}"
            if consensus == "bft"
            else f"--raft-election-timeout-ms={raft_election_timeout}"
        )

        cmd = [
            bin_path,
            f"--enclave-file={enclave_path}",
            f"--enclave-type={enclave_type}",
            f"--node-address={make_address(host, node_port)}",
            f"--node-address-file={self.node_address_path}",
            f"--rpc-address={make_address(host, rpc_port)}",
            f"--rpc-address-file={self.rpc_address_path}",
            f"--public-rpc-address={make_address(pubhost, rpc_port)}",
            f"--ledger-dir={self.ledger_dir_name}",
            f"--node-cert-file={self.pem}",
            f"--host-log-level={host_log_level}",
            election_timeout_arg,
            f"--consensus={consensus}",
            f"--worker-threads={worker_threads}",
        ]

        if log_format_json:
            cmd += ["--log-format-json"]

        if sig_tx_interval:
            cmd += [f"--sig-tx-interval={sig_tx_interval}"]

        if sig_ms_interval:
            cmd += [f"--sig-ms-interval={sig_ms_interval}"]

        if memory_reserve_startup:
            cmd += [f"--memory-reserve-startup={memory_reserve_startup}"]

        if ledger_chunk_bytes:
            cmd += [f"--ledger-chunk-bytes={ledger_chunk_bytes}"]

        if domain:
            cmd += [f"--domain={domain}"]

        if snapshot_tx_interval:
            cmd += [f"--snapshot-tx-interval={snapshot_tx_interval}"]

        if start_type == StartType.new:
            cmd += [
                "start",
                "--network-cert-file=networkcert.pem",
                f"--gov-script={os.path.basename(gov_script)}",
            ]
            if members_info is None:
                raise ValueError(
                    "Starting node should be given at least one pair member certificate, member public encryption key"
                )
            for mc, mk in members_info:
                cmd += [f"--member-info={mc},{mk}"]
                data_files.append(os.path.join(self.common_dir, mc))
                data_files.append(os.path.join(self.common_dir, mk))
            data_files += [os.path.join(os.path.basename(self.common_dir), gov_script)]
        elif start_type == StartType.join:
            cmd += [
                "join",
                "--network-cert-file=networkcert.pem",
                f"--target-rpc-address={target_rpc_address}",
                f"--join-timer={join_timer}",
            ]
            data_files += [os.path.join(self.common_dir, "networkcert.pem")]
        elif start_type == StartType.recover:
            cmd += ["recover", "--network-cert-file=networkcert.pem"]
        else:
            raise ValueError(
                f"Unexpected CCFRemote start type {start_type}. Should be start, join or recover"
            )

        env = {}
        self.profraw = None
        if enclave_type == "virtual":
            env["UBSAN_OPTIONS"] = "print_stacktrace=1"
            env["LSAN_OPTIONS"] = "verbosity=1:log_threads=1"
            if coverage_enabled(lib_path):
                self.profraw = f"{uuid.uuid4()}-{local_node_id}_{os.path.basename(lib_path)}.profraw"
                env["LLVM_PROFILE_FILE"] = self.profraw

        oe_log_level = CCF_TO_OE_LOG_LEVEL.get(host_log_level)
        if oe_log_level:
            env["OE_LOG_LEVEL"] = oe_log_level

        self.remote = remote_class(
            local_node_id,
            host,
            exe_files,
            data_files,
            cmd,
            workspace,
            label,
            common_dir,
            env,
            log_format_json,
        )

    def setup(self):
        self.remote.setup()

    def start(self):
        self.remote.start()

    def suspend(self):
        return self.remote.suspend()

    def resume(self):
        self.remote.resume()

    def get_startup_files(self, dst_path):
        self.remote.get(self.pem, dst_path)
        self.remote.get(self.node_address_path, dst_path)
        self.remote.get(self.rpc_address_path, dst_path)
        if self.start_type in {StartType.new, StartType.recover}:
            self.remote.get("networkcert.pem", dst_path)
            self.remote.get("network_enc_pubk.pem", dst_path)

    def debug_node_cmd(self):
        return self.remote.debug_node_cmd()

    def stop(self):
        errors, fatal_errors = [], []
        try:
            errors, fatal_errors = self.remote.stop()
        except Exception:
            LOG.exception("Failed to shut down {} cleanly".format(self.local_node_id))
        if self.profraw:
            try:
                self.remote.get(self.profraw, self.common_dir)
            except Exception:
                LOG.info(f"Could not retrieve {self.profraw}")
        return errors, fatal_errors

    def check_done(self):
        return self.remote.check_done()

    def set_perf(self):
        self.remote.set_perf()

    def get_ledger(self):
        self.remote.get(self.ledger_dir_name, self.common_dir)
        return os.path.join(self.common_dir, self.ledger_dir_name)

    def get_snapshots(self, pre_condition_func=lambda src_dir, _: True):
        self.remote.get(
            self.snapshot_dir_name,
            self.common_dir,
            pre_condition_func=pre_condition_func,
        )
        return os.path.join(self.common_dir, self.snapshot_dir_name)

    def ledger_path(self):
        return os.path.join(self.remote.root, self.ledger_dir_name)


@contextmanager
def ccf_remote(*args, **kwargs):
    """
    Context Manager wrapper for CCFRemote
    """
    remote = CCFRemote(*args, **kwargs)
    try:
        remote.setup()
        remote.start()
        yield remote
    finally:
        remote.stop()


class StartType(Enum):
    new = 0
    join = 1
    recover = 2
