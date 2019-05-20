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

from loguru import logger as LOG

USER = getpass.getuser()
DBG = os.getenv("DBG", "cgdb")


def tmpdir_name(node_name):
    elements = [USER]
    job_name = os.getenv("JOB_NAME", None)
    if job_name:
        elements.append(job_name.replace("/", "_"))
    elements.append(node_name)
    return "_".join(elements)


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
    try:
        errors = 0
        with open(out_path, "r") as lines:
            for line in lines:
                if line.startswith("[!]") or line.startswith("[!!]"):
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


class SSHRemote(CmdMixin):
    def __init__(self, name, hostname, files, cmd):
        """
        Runs a command on a remote host, through an SSH connection. A temporary
        directory is created, and some files can be shipped over. The command is
        run out of that directory.

        Note that the name matters, since the temporary directory that will be first
        deleted, then created and populated is /tmp/`tmpdir_name(name)`. There is deliberately no
        cleanup on shutdown, to make debugging/inspection possible.

        setup() connects, creates the directory and ships over the files
        start() runs the specified command
        stop()  disconnects, which shuts down the command via SIGHUP
        restart() reconnects and reruns the specified command
        """
        self.hostname = hostname
        self.files = files
        self.cmd = cmd
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.root = os.path.join("/tmp", tmpdir_name(name))
        self.name = name

    def _rc(self, cmd):
        LOG.info("[{}] {}".format(self.hostname, cmd))
        _, stdout, _ = self.client.exec_command(cmd)
        return stdout.channel.recv_exit_status()

    def _connect(self):
        LOG.debug("[{}] connect".format(self.hostname))
        self.client.connect(self.hostname)

    def _setup_files(self):
        assert self._rc("rm -rf {}".format(self.root)) == 0
        assert self._rc("mkdir {}".format(self.root)) == 0
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

    def get(self, filename, timeout=60):
        """
        Get file called `filename` under the root of the remote. If the
        file is missing, wait for timeout, and raise an exception.

        If the file is present, it is copied to the CWD on the caller's host.

        This call spins up a separate client because we don't want to interrupt
        the main cmd that may be running.
        """
        with sftp_session(self.hostname) as session:
            for seconds in range(timeout):
                try:
                    session.get(os.path.join(self.root, filename), filename)
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

    def start(self):
        """
        Start cmd on the remote host. stdout and err are captured to file locally.

        We create a pty on thre remote host under which to run the command, so as to
        get a SIGHUP on disconnection.
        """
        cmd = self._cmd()
        LOG.info("[{}] {}".format(self.hostname, cmd))
        self.client.exec_command(cmd, get_pty=True)

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
        return "cd {} && stdbuf -o0 ./{} 1>out 2>err 0</dev/null".format(
            self.root, " ".join(self.cmd)
        )

    def _dbg(self):
        return "cd {} && {} --args ./{}".format(self.root, DBG, " ".join(self.cmd))

    def wait_for_stdout_line(self, line, timeout):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.hostname)
        try:
            for _ in range(timeout):
                _, stdout, _ = self.client.exec_command(
                    "grep -F '{}' {}/out".format(line, self.root)
                )
                if stdout.channel.recv_exit_status() == 0:
                    return
                time.sleep(1)
            raise ValueError(
                "{} not found in stdout after {} seconds".format(line, timeout)
            )
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
    def __init__(self, name, hostname, files, cmd):
        """
        Local Equivalent to the SSHRemote
        """
        self.hostname = hostname
        self.files = files
        self.cmd = cmd
        self.root = os.path.join("/tmp", tmpdir_name(name))
        self.proc = None
        self.stdout = None
        self.stderr = None

    def _rc(self, cmd):
        LOG.info("[{}] {}".format(self.hostname, cmd))
        return subprocess.call(cmd, shell=True)

    def _setup_files(self):
        assert self._rc("rm -rf {}".format(self.root)) == 0
        assert self._rc("mkdir {}".format(self.root)) == 0
        for path in self.files:
            tgt_path = os.path.join(self.root, os.path.basename(path))
            assert self._rc("cp {} {}".format(path, tgt_path)) == 0
        executable = self.cmd[0]
        if executable.startswith("./"):
            executable = executable[2:]
        else:
            self.cmd[0] = "./{}".format(self.cmd[0])
        assert self._rc("chmod +x {}".format(os.path.join(self.root, executable))) == 0

    def get(self, filename, timeout=60):
        path = os.path.join(self.root, filename)
        for _ in range(timeout):
            if os.path.exists(path):
                break
            time.sleep(1)
        else:
            raise ValueError(path)
        assert self._rc("cp {} {}".format(path, filename)) == 0

    def list_files(self):
        return os.listdir(self.root)

    def start(self):
        """
        Start cmd. stdout and err are captured to file locally.
        """
        cmd = self._cmd()
        LOG.info("[{}] {}".format(self.hostname, cmd))
        self.stdout = open(os.path.join(self.root, "out"), "wb")
        self.stderr = open(os.path.join(self.root, "err"), "wb")
        self.proc = subprocess.Popen(
            self.cmd, cwd=self.root, stdout=self.stdout, stderr=self.stderr
        )

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


class CCFRemote(object):
    BIN = "cchost"
    DEPS = []

    def __init__(
        self,
        lib_path,
        node_id,
        host,
        pubhost,
        raft_port,
        tls_port,
        remote_class,
        enclave_type,
        log_level,
        expect_quote,
        sig_max_tx,
        sig_max_ms,
        node_status,
        election_timeout,
        memory_reserve_startup,
        notify_server,
        ledger_file=None,
        sealed_secrets=None,
    ):
        """
        Run a ccf binary on a remote host.
        """
        self.node_id = node_id
        self.host = host
        self.pubhost = pubhost
        self.raft_port = raft_port
        self.tls_port = tls_port
        self.pem = "{}.pem".format(node_id)
        self.quote = None
        self.node_status = node_status
        # Only expect a quote if the enclave is not virtual and quotes have
        # not been explictly disabled
        if enclave_type != "virtual" and expect_quote:
            self.quote = "quote{}.bin".format(node_id)
        self.BIN = infra.path.build_bin_path(self.BIN, enclave_type)
        self.ledger_file = ledger_file
        self.ledger_file_name = (
            os.path.basename(ledger_file)
            if ledger_file
            else "{}.ledger".format(node_id)
        )

        cmd = [
            self.BIN,
            "--enclave-file={}".format(lib_path),
            "--raft-election-timeout-ms={}".format(election_timeout),
            "--raft-host={}".format(host),
            "--raft-port={}".format(raft_port),
            "--tls-host={}".format(host),
            "--tls-pubhost={}".format(pubhost),
            "--tls-port={}".format(tls_port),
            "--ledger-file={}".format(self.ledger_file_name),
            "--node-cert-file={}".format(self.pem),
            "--enclave-type={}".format(enclave_type),
            "--log-level={}".format(log_level),
        ]

        if sig_max_tx is not None:
            cmd += ["--sig-max-tx={}".format(sig_max_tx)]

        if sig_max_ms is not None:
            cmd += ["--sig-max-ms={}".format(sig_max_ms)]

        if memory_reserve_startup is not None:
            cmd += ["--memory-reserve-startup={}".format(memory_reserve_startup)]

        if notify_server is not None:
            notify_server_host, *notify_server_port = notify_server.split(":")

            if not notify_server_host or not (
                notify_server_port and notify_server_port[0]
            ):
                raise ValueError(
                    "Notification server host:port configuration is invalid"
                )

            cmd += ["--notify-server-host={}".format(notify_server_host)]
            cmd += ["--notify-server-port={}".format(notify_server_port[0])]

        if self.quote is not None:
            cmd.append("--quote-file={}".format(self.quote))

        self.remote = remote_class(
            node_id,
            host,
            [self.BIN, lib_path]
            + self.DEPS
            + ([self.ledger_file] if self.ledger_file else [])
            + ([sealed_secrets] if sealed_secrets else []),
            cmd,
        )

    def setup(self):
        self.remote.setup()

    def start(self):
        self.remote.start()
        return self.info()

    def restart(self):
        self.remote.restart()
        return self.info()

    def info(self):
        self.remote.get(self.pem)
        quote_bytes = []
        if self.quote:
            self.remote.get(self.quote)
            quote_bytes = infra.path.quote_bytes(self.quote)

        return {
            "host": self.host,
            "raftport": str(self.raft_port),
            "pubhost": self.pubhost,
            "tlsport": str(self.tls_port),
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
            LOG.exception("Failed to shut down {} cleanly".format(self.node_id))

    def wait_for_stdout_line(self, line, timeout=5):
        return self.remote.wait_for_stdout_line(line, timeout)

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


@contextmanager
def ccf_remote(
    lib_path, node_id, host, pubhost, raft_port, tls_port, args, remote_class
):
    """
    Context Manager wrapper for CCFRemote
    """
    remote = CCFRemote(
        lib_path, node_id, host, pubhost, raft_port, tls_port, args, remote_class
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
