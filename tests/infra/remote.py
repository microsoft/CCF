# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import time
from enum import Enum
import paramiko
import logging
import subprocess
import getpass
from contextlib import contextmanager
import infra.path
import json
import uuid
import ctypes
import signal
import re

from loguru import logger as LOG

DBG = os.getenv("DBG", "cgdb")

_libc = ctypes.CDLL("libc.so.6")


def _term_on_pdeathsig():
    # usr/include/linux/prctl.h: #define PR_SET_PDEATHSIG 1
    _libc.prctl(1, signal.SIGTERM)


def popen(*args, **kwargs):
    kwargs["preexec_fn"] = _term_on_pdeathsig
    return subprocess.Popen(*args, **kwargs)


def coverage_enabled(bin):
    return (
        subprocess.run(
            f"nm -C {bin} | grep __llvm_coverage_mapping", shell=True
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
    error_filter = ["[fail]", "[fatal]"]
    try:
        errors = 0
        with open(out_path, "r") as lines:
            for line in lines:
                if any(x in line for x in error_filter):
                    LOG.error("{}: {}".format(out_path, line.rstrip()))
                    errors += 1
        if errors:
            try:
                with open(err_path, "r") as lines:
                    LOG.error("{} contents:".format(err_path))
                    LOG.error(lines.read())
            except IOError:
                LOG.exception("Could not read err output {}".format(err_path))
    except IOError:
        LOG.exception("Could not check output {} for errors".format(out_path))


class CmdMixin(object):
    def set_recovery(self):
        self.cmd.append("--start=recover")
        self.cmd = list(dict.fromkeys(self.cmd))

    def set_perf(self):
        self.cmd = [
            "perf",
            "record",
            "--freq=1000",
            "--call-graph=dwarf",
            "-s",
        ] + self.cmd

    def _print_upload_perf(self, name, metrics, lines):
        for line in lines:
            LOG.debug(line.decode())
            res = re.search("=> (.*)tx/s", line.decode())
            if res:
                results_uploaded = True
                metrics.put(name, float(res.group(1)))


class SSHRemote(CmdMixin):
    def __init__(
        self, name, hostname, exe_files, data_files, cmd, workspace, label, env=None
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
        restart() reconnects and reruns the specified command
        """
        self.hostname = hostname
        # For SSHRemote, both executable files (host and enclave) and data
        # files (ledger, secrets) are copied to the remote
        self.files = exe_files
        self.files += data_files
        self.cmd = cmd
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.root = os.path.join(workspace, label + "_" + name)
        self.name = name
        self.env = env or {}

    def _rc(self, cmd):
        LOG.info("[{}] {}".format(self.hostname, cmd))
        _, stdout, _ = self.client.exec_command(cmd)
        return stdout.channel.recv_exit_status()

    def _connect(self):
        LOG.debug("[{}] connect".format(self.hostname))
        self.client.connect(self.hostname)

    def _setup_files(self):
        assert self._rc("rm -rf {}".format(self.root)) == 0
        assert self._rc("mkdir -p {}".format(self.root)) == 0
        session = self.client.open_sftp()
        for path in self.files:
            tgt_path = os.path.join(self.root, os.path.basename(path))
            LOG.info("[{}] copy {} from {}".format(self.hostname, tgt_path, path))
            session.put(path, tgt_path)
        session.close()
        executable = self.cmd[0]
        if executable.startswith("./"):
            executable = executable[2:]
        assert self._rc("chmod +x {}".format(os.path.join(self.root, executable))) == 0

    def get(self, filename, timeout=60, targetname=None):
        """
        Get file called `filename` under the root of the remote. If the
        file is missing, wait for timeout, and raise an exception.

        If the file is present, it is copied to the CWD on the caller's
        host, as `targetname` if it is set.

        This call spins up a separate client because we don't want to interrupt
        the main cmd that may be running.
        """
        with sftp_session(self.hostname) as session:
            for seconds in range(timeout):
                try:
                    targetname = targetname or filename
                    session.get(os.path.join(self.root, filename), targetname)
                    LOG.debug(
                        "[{}] found {} after {}s".format(
                            self.hostname, filename, seconds
                        )
                    )
                    break
                except Exception:
                    time.sleep(1)
            else:
                raise ValueError(filename)

    def list_files(self, timeout=60):
        files = []
        with sftp_session(self.hostname) as session:
            for seconds in range(timeout):
                try:
                    files = session.listdir(self.root)

                    break
                except Exception:
                    time.sleep(1)

            else:
                raise ValueError(self.root)
        return files

    def get_logs(self):
        with sftp_session(self.hostname) as session:
            for filename in ("err", "out"):
                try:
                    filepath = os.path.join(self.root, filename)
                    local_filepath = "{}_{}_{}".format(
                        self.hostname, filename, self.name
                    )
                    session.get(filepath, local_filepath)
                    LOG.info("Downloaded {}".format(local_filepath))
                except Exception:
                    LOG.warning(
                        "Failed to download {} from {}".format(filepath, self.hostname)
                    )

    def _wait_for_termination(self, stdout, timeout=10):
        chan = stdout.channel
        for _ in range(timeout):
            if chan.exit_status_ready():
                if chan.recv_exit_status() is not 0:
                    raise RuntimeError("SSHRemote did not terminate gracefully")
                else:
                    LOG.success("Command finished")
                    return
            else:
                LOG.error("Command not ready")
            time.sleep(1)
        raise TimeoutError("Timed out waiting for SSHRemote to terminate")

    def start(self, wait_for_termination=False):
        """
        Start cmd on the remote host. stdout and err are captured to file locally.

        We create a pty on the remote host under which to run the command, so as to
        get a SIGHUP on disconnection.
        """
        cmd = self._cmd()
        LOG.info("[{}] {}".format(self.hostname, cmd))
        stdin, stdout, stderr = self.client.exec_command(cmd, get_pty=True)

        if wait_for_termination:
            self._wait_for_termination(stdout)

    def stop(self):
        """
        Disconnect the client, and therefore shut down the command as well.
        """
        LOG.info("[{}] closing".format(self.hostname))
        self.get_logs()
        log_errors(
            "{}_out_{}".format(self.hostname, self.name),
            "{}_err_{}".format(self.hostname, self.name),
        )
        self.client.close()

    def restart(self):
        self._connect()
        self.start()

    def setup(self):
        """
        Connect to the remote host, empty the temporary directory if it exsits,
        and populate it with the initial set of files.
        """
        self._connect()
        self._setup_files()

    def _cmd(self):
        env = " ".join(f"{key}={value}" for key, value in self.env.items())
        cmd = " ".join(self.cmd)
        return f"cd {self.root} && {env} ./{cmd} 1>out 2>err 0</dev/null"

    def _dbg(self):
        return "cd {} && {} --args ./{}".format(self.root, DBG, " ".join(self.cmd))

    def _connect_new(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.hostname)
        return client

    def wait_for_stdout_line(self, line, timeout):
        client = self._connect_new()
        try:
            for _ in range(timeout):
                _, stdout, _ = client.exec_command(f"grep -F '{line}' {self.root}/out")
                if stdout.channel.recv_exit_status() == 0:
                    return
                time.sleep(1)
            raise ValueError(
                "{} not found in stdout after {} seconds".format(line, timeout)
            )
        finally:
            client.close()

    def print_and_upload_result(self, name, metrics, lines):
        client = self._connect_new()
        try:
            _, stdout, _ = client.exec_command(f"tail -{lines} {self.root}/out")
            if stdout.channel.recv_exit_status() == 0:
                LOG.success(f"Result for {self.name}:")
                self._print_upload_perf(name, metrics, stdout.read().splitlines())
                return
        finally:
            client.close()


@contextmanager
def ssh_remote(name, hostname, files, cmd):
    """
    Context Manager wrapper for SSHRemote
    """
    remote = SSHRemote(name, hostname, files, cmd)
    try:
        remote.setup()
        remote.start()
        yield remote
    finally:
        remote.stop()


class LocalRemote(CmdMixin):
    def __init__(
        self, name, hostname, exe_files, data_files, cmd, workspace, label, env=None
    ):
        """
        Local Equivalent to the SSHRemote
        """
        self.hostname = hostname
        self.exe_files = exe_files
        self.data_files = data_files
        self.cmd = cmd
        self.root = os.path.join(workspace, label + "_" + name)
        self.proc = None
        self.stdout = None
        self.stderr = None
        self.env = env
        self.name = name

    def _rc(self, cmd):
        LOG.info("[{}] {}".format(self.hostname, cmd))
        return subprocess.call(cmd, shell=True)

    def _setup_files(self):
        assert self._rc("rm -rf {}".format(self.root)) == 0
        assert self._rc("mkdir -p {}".format(self.root)) == 0
        for path in self.exe_files:
            dst_path = os.path.join(self.root, os.path.basename(path))
            src_path = os.path.join(os.getcwd(), path)
            assert self._rc("ln -s {} {}".format(src_path, dst_path)) == 0
        for path in self.data_files:
            dst_path = os.path.join(self.root, os.path.basename(path))
            src_path = os.path.join(os.getcwd(), path)
            assert self._rc("cp {} {}".format(src_path, dst_path)) == 0

        # Make sure relative paths include current directory. Absolute paths will be unaffected
        self.cmd[0] = os.path.join(".", os.path.normpath(self.cmd[0]))

    def get(self, filename, timeout=60, targetname=None):
        path = os.path.join(self.root, filename)
        for _ in range(timeout):
            if os.path.exists(path):
                break
            time.sleep(1)
        else:
            raise ValueError(path)
        targetname = targetname or filename
        assert self._rc("cp {} {}".format(path, targetname)) == 0

    def list_files(self):
        return os.listdir(self.root)

    def _wait_for_termination(self, timeout=10):
        try:
            self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            raise TimeoutError("Timed out waiting for LocalRemote to terminate")

        if self.proc.returncode is not 0:
            raise RuntimeError("LocalRemote did not terminate gracefully")

    def start(self, wait_for_termination=False, timeout=10):
        """
        Start cmd. stdout and err are captured to file locally.
        """
        cmd = self._cmd()
        LOG.info(f"[{self.hostname}] {cmd} (env: {self.env})")
        self.stdout = open(os.path.join(self.root, "out"), "wb")
        self.stderr = open(os.path.join(self.root, "err"), "wb")
        self.proc = popen(
            self.cmd,
            cwd=self.root,
            stdout=self.stdout,
            stderr=self.stderr,
            env=self.env,
        )
        if wait_for_termination:
            self._wait_for_termination()

    def stop(self):
        """
        Disconnect the client, and therefore shut down the command as well.
        """
        LOG.info("[{}] closing".format(self.hostname))
        if self.proc:
            self.proc.terminate()
            self.proc.wait()
            if self.stdout:
                self.stdout.close()
            if self.stderr:
                self.stderr.close()
            log_errors(os.path.join(self.root, "out"), os.path.join(self.root, "err"))

    def restart(self):
        self.start()

    def setup(self):
        """
        Empty the temporary directory if it exists,
        and populate it with the initial set of files.
        """
        self._setup_files()

    def _cmd(self):
        return "cd {} && {} 1>out 2>err".format(self.root, " ".join(self.cmd))

    def _dbg(self):
        return "cd {} && {} --args {}".format(self.root, DBG, " ".join(self.cmd))

    def wait_for_stdout_line(self, line, timeout):
        for _ in range(timeout):
            with open(os.path.join(self.root, "out"), "rb") as out:
                for out_line in out:
                    if line.strip() in out_line.strip().decode():
                        return
            time.sleep(1)
        raise ValueError(
            "{} not found in stdout after {} seconds".format(line, timeout)
        )

    def print_and_upload_result(self, name, metrics, line):
        with open(os.path.join(self.root, "out"), "rb") as out:
            lines = out.read().splitlines()
            result = lines[-line:]
            LOG.success(f"Result for {self.name}:")
            self._print_upload_perf(name, metrics, result)


CCF_TO_OE_LOG_LEVEL = {
    "trace": "VERBOSE",
    "debug": "INFO",
    "info": "WARNING",
    "fail": "ERROR",
    "fatal": "FATAL",
}


class CCFRemote(object):
    BIN = "cchost"
    DEPS = []

    def __init__(
        self,
        lib_path,
        local_node_id,
        host,
        pubhost,
        node_port,
        rpc_port,
        remote_class,
        enclave_type,
        verify_quote,
        workspace,
        label,
        other_quote=None,
        other_quoted_data=None,
        log_level="info",
        ignore_quote=False,
        sig_max_tx=1000,
        sig_max_ms=1000,
        node_status="pending",
        election_timeout=1000,
        memory_reserve_startup=0,
        notify_server=None,
        ledger_file=None,
        sealed_secrets=None,
    ):
        """
        Run a ccf binary on a remote host.
        """
        self.local_node_id = local_node_id
        self.host = host
        self.pubhost = pubhost
        self.node_port = node_port
        self.rpc_port = rpc_port
        self.pem = "{}.pem".format(local_node_id)
        self.quote = None
        self.node_status = node_status
        self.verify_quote = verify_quote
        # Only expect a quote if the enclave is not virtual and quotes have
        # not been explictly ignored
        if enclave_type != "virtual" and not ignore_quote:
            self.quote = f"quote{local_node_id}.bin"
        self.BIN = infra.path.build_bin_path(self.BIN, enclave_type)
        self.ledger_file = ledger_file
        self.ledger_file_name = (
            os.path.basename(ledger_file) if ledger_file else f"{local_node_id}.ledger"
        )

        cmd = [self.BIN, f"--enclave-file={lib_path}"]

        # If the remote needs to verify the quote, only a subset of arguments are required
        if self.verify_quote:
            cmd += ["--start=verify"]

            if not other_quote:
                raise ValueError(
                    "Quote should be specified when starting remote in verify mode"
                )
            if not other_quoted_data:
                raise ValueError(
                    "Quoted data should be specified when starting remote in verify mode"
                )

            cmd += [f"--quote-file={other_quote}", f"--quoted-data={other_quoted_data}"]
        else:
            cmd = [
                self.BIN,
                f"--enclave-file={lib_path}",
                f"--raft-election-timeout-ms={election_timeout}",
                f"--node-address={host}:{node_port}",
                f"--rpc-address={host}:{rpc_port}",
                f"--ledger-file={self.ledger_file_name}",
                f"--node-cert-file={self.pem}",
                f"--enclave-type={enclave_type}",
                f"--log-level={log_level}",
            ]

            if sig_max_tx:
                cmd += [f"--sig-max-tx={sig_max_tx}"]

            if sig_max_ms:
                cmd += [f"--sig-max-ms={sig_max_ms}"]

            if memory_reserve_startup:
                cmd += [f"--memory-reserve-startup={memory_reserve_startup}"]

            if notify_server:
                notify_server_host, *notify_server_port = notify_server.split(":")

                if not notify_server_host or not (
                    notify_server_port and notify_server_port[0]
                ):
                    raise ValueError(
                        "Notification server host:port configuration is invalid"
                    )

                cmd += [
                    f"--notify-server-address={notify_server_host}:{notify_server_port[0]}"
                ]

            if self.quote:
                cmd.append(f"--quote-file={self.quote}")

        env = {}
        self.profraw = None
        if enclave_type == "virtual" and coverage_enabled(lib_path):
            self.profraw = (
                f"{uuid.uuid4()}-{local_node_id}_{os.path.basename(lib_path)}.profraw"
            )
            env["LLVM_PROFILE_FILE"] = self.profraw

        oe_log_level = CCF_TO_OE_LOG_LEVEL.get(log_level)
        if oe_log_level:
            env["OE_LOG_LEVEL"] = oe_log_level

        self.remote = remote_class(
            local_node_id,
            host,
            [self.BIN, lib_path] + self.DEPS,
            ([self.ledger_file] if self.ledger_file else [])
            + ([sealed_secrets] if sealed_secrets else []),
            cmd,
            workspace,
            label,
            env,
        )

    def setup(self):
        self.remote.setup()

    def start(self):
        wait_for_termination = self.verify_quote
        self.remote.start(wait_for_termination)

    def restart(self):
        self.remote.restart()

    def info(self):
        self.remote.get(self.pem)
        quote_bytes = []
        if self.quote:
            self.remote.get(self.quote)
            quote_bytes = infra.path.quote_bytes(self.quote)

        return {
            "host": self.host,
            "nodeport": str(self.node_port),
            "pubhost": self.pubhost,
            "rpcport": str(self.rpc_port),
            "cert": infra.path.cert_bytes(self.pem),
            "quote": quote_bytes,
            "status": NodeStatus[self.node_status].value,
        }

    def node_cmd(self):
        return self.remote._cmd()

    def debug_node_cmd(self):
        return self.remote._dbg()

    def stop(self):
        try:
            self.remote.stop()
        except Exception:
            LOG.exception("Failed to shut down {} cleanly".format(self.local_node_id))
        if self.profraw:
            try:
                self.remote.get(self.profraw)
            except Exception:
                LOG.info(f"Could not retrieve {self.profraw}")

    def wait_for_stdout_line(self, line, timeout=5):
        return self.remote.wait_for_stdout_line(line, timeout)

    def print_and_upload_result(self, name, metrics, lines):
        self.remote.print_and_upload_result(name, metrics, lines)

    def set_recovery(self):
        self.remote.set_recovery()

    def set_perf(self):
        self.remote.set_perf()

    def get_sealed_secrets(self):
        files = self.remote.list_files()
        sealed_secrets_files = []
        for f in files:
            if f.startswith("sealed_secrets."):
                sealed_secrets_files.append(f)

        latest_sealed_secrets = sorted(sealed_secrets_files, reverse=True)[0]
        self.remote.get(latest_sealed_secrets)

        return latest_sealed_secrets

    def get_ledger(self):
        self.remote.get(self.ledger_file_name)
        return self.ledger_file_name

    def ledger_path(self):
        return os.path.join(self.remote.root, self.ledger_file_name)

    def get_quote(self):
        self.remote.get(self.quote)
        return os.path.join(self.remote.root, self.quote)

    def get_cert(self):
        self.remote.get(self.pem)
        return os.path.join(self.remote.root, self.pem)


@contextmanager
def ccf_remote(
    lib_path, local_node_id, host, pubhost, node_port, rpc_port, args, remote_class
):
    """
    Context Manager wrapper for CCFRemote
    """
    remote = CCFRemote(
        lib_path, local_node_id, host, pubhost, node_port, rpc_port, args, remote_class
    )
    try:
        remote.setup()
        remote.start()
        yield remote
    finally:
        remote.stop()


class NodeStatus(Enum):
    pending = 0
    trusted = 1
    retired = 2
