# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import time
from enum import Enum, auto
import subprocess
import infra.path
import signal
import re
import shutil
import infra.platform_detection
from jinja2 import Environment, FileSystemLoader, select_autoescape
import json
import infra.snp as snp
import ccf._versionifier
from packaging.version import (  # type: ignore
    Version,
)

from loguru import logger as LOG

DBG = os.getenv("DBG", "lldb")

# Duration after which unresponsive node is declared as crashed on startup
REMOTE_STARTUP_TIMEOUT_S = 5
FILE_TIMEOUT_S = 60


class CmdMixin(object):
    perfable = True

    @property
    def cmd(self):
        if self.perfable and os.getenv("CCF_PERF"):
            return ["perf", "record"] + self._cmd
        else:
            return self._cmd

    def _get_perf(self, lines):
        pattern = "=> (.*)tx/s"
        for line in lines:
            LOG.debug(line.decode())
            res = re.search(pattern, line.decode())
            if res:
                return float(res.group(1))
        raise ValueError(f"No performance result found (pattern is {pattern})")


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
        **kwargs,
    ):
        self.hostname = hostname
        self.exe_files = set(exe_files)
        self.data_files = data_files
        self._cmd = cmd
        self.root = os.path.join(workspace, name)
        self.common_dir = common_dir
        self.proc = None
        self.stdout = None
        self.stderr = None
        self.env = env or {}
        self.name = name
        self.out = os.path.join(self.root, "out")
        self.err = os.path.join(self.root, "err")
        self.stack_trace = os.path.join(self.root, "stack_trace")
        self._shutdown_timeout = 10

    @property
    def shutdown_timeout(self):
        return self._shutdown_timeout

    @shutdown_timeout.setter
    def shutdown_timeout(self, value):
        self._shutdown_timeout = value

    @staticmethod
    def make_host(host):
        return host

    @staticmethod
    def get_node_address(addr):
        return addr

    def _rc(self, cmd):
        LOG.info("[{}] {}".format(self.hostname, cmd))
        return subprocess.call(cmd, shell=True)

    def cp(self, src_path, dst_path):
        if os.path.isdir(src_path):
            assert self._rc("rm -rf {}".format(os.path.join(dst_path))) == 0
            assert self._rc("cp -r {} {}".format(src_path, dst_path)) == 0
        else:
            assert self._rc("cp {} {}".format(src_path, dst_path)) == 0

    def _setup_files(self, use_links: bool):
        assert self._rc("rm -rf {}".format(self.root)) == 0
        assert self._rc("mkdir -p {}".format(self.root)) == 0
        for path in self.exe_files:
            dst_path = os.path.normpath(os.path.join(self.root, os.path.basename(path)))
            src_path = os.path.normpath(os.path.join(os.getcwd(), path))
            if use_links:
                assert self._rc("ln -s {} {}".format(src_path, dst_path)) == 0
            else:
                assert self._rc("cp {} {}".format(src_path, dst_path)) == 0
        for path in self.data_files:
            if len(path) > 0:
                dst_path = os.path.join(self.root, os.path.basename(path))
                self.cp(path, dst_path)

    def get(
        self,
        src_path,
        dst_path,
        timeout=FILE_TIMEOUT_S,
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
            status = "not started"
            if self.proc is not None:
                if self.proc.poll() is None:
                    status = "running"
                else:
                    status = f"stopped (rc: {self.proc.poll()})"
            raise ValueError(f"{path} not found after {timeout} seconds, {status}")
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
        LOG.info(f"[{self.hostname}] {cmd} (env: {self.env.keys()})")
        self.stdout = open(self.out, "wb")
        self.stderr = open(self.err, "wb")
        self.proc = subprocess.Popen(
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

    def hangup(self):
        self.proc.send_signal(signal.SIGHUP)

    def get_logs(self):
        return self.out, self.err

    def get_stack_trace(self, timeout=20):
        if shutil.which("lldb") != "":
            # To avoid errors on decoding lldb output as utf-8.
            # We shoud find a way to force lldb to use utf-8.
            errors = "ignore"
            try:
                command = [
                    "lldb",
                    "--batch",  # Ensure non-interactive
                    "-p",
                    f"{self.proc.pid}",
                    "--one-line",
                    "thread backtrace all",
                    "--one-line",
                    "quit",
                ]
                if os.geteuid() != 0:
                    # Add sudo if not root
                    command.insert(0, "sudo")
                completed_lldb_process = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    errors=errors,
                    text=True,
                    timeout=timeout,
                    check=True,
                )
                return completed_lldb_process.stdout
            except subprocess.TimeoutExpired:
                LOG.info(
                    "Failed to get stack trace. lldb did not finish within {lldb_timeout} seconds."
                )
            except Exception as e:
                LOG.info(f"Failed to get stack trace: {e}")
        else:
            LOG.info("Couldn't find lldb installed")

    def log_stack_trace(self, timeout=20):
        st = self.get_stack_trace(timeout=timeout)
        if st:
            with open(self.stack_trace, "w", encoding="utf-8") as f:
                f.write(st)
            LOG.error(
                f"Stack trace of process {self.proc.pid} written to {self.stack_trace}"
            )

    def sigterm(self):
        self.proc.terminate()

    def sigkill(self):
        self.proc.send_signal(signal.SIGKILL)

    def stop(self):
        """
        Disconnect the client, and therefore shut down the command as well.
        """
        LOG.info("[{}] closing".format(self.hostname))
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(self._shutdown_timeout)
            except subprocess.TimeoutExpired:
                LOG.exception(
                    f"Process didn't finish within {self._shutdown_timeout} seconds. Trying to get stack trace..."
                )
                st = self.get_stack_trace()
                if st:
                    LOG.error(f"Stack trace of process {self.proc.pid}:\n{st}")
                raise

            exit_code = self.proc.returncode
            if exit_code is not None and exit_code < 0:
                signal_str = signal.strsignal(-exit_code)
                LOG.error(f"{self.hostname} exited with signal: {signal_str}")
            if self.stdout:
                self.stdout.close()
            if self.stderr:
                self.stderr.close()

    def setup(self, use_links=True):
        """
        Empty the temporary directory if it exists,
        and populate it with the initial set of files.
        """
        self._setup_files(use_links)

    def get_cmd(self, include_dir=True):
        cmd = f"cd {self.root} && " if include_dir else ""
        cmd += f'{" ".join(self.cmd)} 1> {self.out} 2> {self.err}'
        return cmd

    def debug_node_cmd(self):
        cmd = " ".join(self.cmd)
        return f"cd {self.root} && {DBG} -- {cmd}"

    def check_done(self):
        return self.proc is not None and self.proc.poll() is not None

    def get_result(self, line_count):
        with open(self.out, "rb") as out:
            lines = out.read().splitlines()
            result = lines[-line_count:]
            return self._get_perf(result)


class CCFRemote(object):
    BIN = "cchost"
    TEMPLATE_CONFIGURATION_FILE = "config.jinja"
    DEPS = []

    def __init__(
        self,
        start_type,
        enclave_file,
        workspace,
        common_dir,
        label="",
        binary_dir=".",
        local_node_id=None,
        host=None,
        ledger_dir=None,
        read_only_ledger_dirs=None,
        snapshots_dir=None,
        read_only_snapshots_dir=None,
        common_read_only_ledger_dir=None,
        constitution=None,
        curve_id=None,
        version=None,
        log_level="Info",
        major_version=None,
        node_address=None,
        config_file=None,
        join_timer_s=None,
        sig_ms_interval=None,
        jwt_key_refresh_interval_s=None,
        election_timeout_ms=None,
        consensus_update_timeout_ms=None,
        node_data_json_file=None,
        service_cert_file="service_cert.pem",
        service_data_json_file=None,
        snp_endorsements_servers=None,
        node_pid_file="node.pid",
        snp_uvm_security_context_dir=None,
        set_snp_uvm_security_context_dir_envvar=True,
        ignore_first_sigterm=False,
        node_container_image=None,
        follow_redirect=True,
        fetch_recent_snapshot=True,
        max_uncommitted_tx_count=0,
        snp_security_policy_file=None,
        snp_uvm_endorsements_file=None,
        snp_endorsements_file=None,
        service_subject_name="CN=CCF Test Service",
        historical_cache_soft_limit=None,
        cose_signatures_issuer="service.example.com",
        cose_signatures_subject="ledger.signature",
        sealed_ledger_secret_location=None,
        previous_sealed_ledger_secret_location=None,
        self_healing_open_cluster_identities=None,
        self_healing_open_identity=None,
        **kwargs,
    ):
        """
        Run a ccf binary on a remote host.
        """

        snp_security_context_directory_envvar = None

        env = kwargs.get("env", {})

        if infra.platform_detection.is_snp():
            env.update(snp.get_aci_env())
            snp_security_context_directory_envvar = (
                snp.ACI_SEV_SNP_ENVVAR_UVM_SECURITY_CONTEXT_DIR
                if set_snp_uvm_security_context_dir_envvar
                and snp.ACI_SEV_SNP_ENVVAR_UVM_SECURITY_CONTEXT_DIR in env
                else None
            )
            if snp_uvm_security_context_dir is not None:
                env[snp_security_context_directory_envvar] = (
                    snp_uvm_security_context_dir
                )
        env["UBSAN_OPTIONS"] = "print_stacktrace=1"
        ubsan_opts = kwargs.get("ubsan_options")
        if ubsan_opts:
            env["UBSAN_OPTIONS"] += ":" + ubsan_opts
        env["TSAN_OPTIONS"] = os.environ.get("TSAN_OPTIONS", "")
        env["ASAN_OPTIONS"] = os.environ.get("ASAN_OPTIONS", "")
        env["ASAN_SYMBOLIZER_PATH"] = os.environ.get("ASAN_SYMBOLIZER_PATH", "")
        env["TSAN_SYMBOLIZER_PATH"] = os.environ.get("TSAN_SYMBOLIZER_PATH", "")

        self.name = f"{label}_{local_node_id}"
        self.start_type = start_type
        self.local_node_id = local_node_id
        self.pem = f"{local_node_id}.pem"
        self.node_address_file = f"{local_node_id}.node_address"
        self.rpc_addresses_file = f"{local_node_id}.rpc_addresses"

        self.BIN = infra.path.build_bin_path(self.BIN, binary_dir=binary_dir)
        # 7.x releases combined binaries and removed the separate cchost entry-point
        if major_version is None or major_version >= 7:
            self.BIN = enclave_file

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

        if self.ledger_dir_name in self.read_only_ledger_dirs_names:
            raise RuntimeError(
                f"Ledger directory named '{self.ledger_dir_name}' already appears in this node's read-only ledger directories, it cannot also be the node's main writeable directory"
            )

        # Snapshots
        self.snapshots_dir = os.path.normpath(snapshots_dir) if snapshots_dir else None
        self.snapshots_dir_name = (
            os.path.basename(self.snapshots_dir)
            if self.snapshots_dir
            else f"{local_node_id}.snapshots"
        )
        self.read_only_snapshots_dir = (
            os.path.normpath(read_only_snapshots_dir)
            if read_only_snapshots_dir
            else None
        )
        self.read_only_snapshots_dir_name = (
            os.path.basename(self.read_only_snapshots_dir)
            if self.read_only_snapshots_dir
            else None
        )

        # Constitution
        constitution = [os.path.basename(f) for f in constitution]
        assert len(set(constitution)) == len(
            constitution
        ), f"Constitution contains files with duplicate names, which is not going to do what you want. Recommend renaming one of them, or improving this infra to copy them to unique names. {constitution=}"

        # SNP endorsements servers
        snp_endorsements_servers = snp_endorsements_servers or []
        snp_endorsements_servers_list = []
        for s in snp_endorsements_servers:
            try:
                server_type, url = s.split(":", 1)
            except ValueError as e:
                raise ValueError(
                    "SNP endorsements servers should be in the format type:url"
                ) from e
            s = {}
            s["type"] = server_type
            s["url"] = url
            s["max_retries_count"] = 4
            snp_endorsements_servers_list.append(s)

        # Default snp_security_policy_file if not set
        if snp_security_policy_file is None:
            snp_security_policy_file = (
                "$UVM_SECURITY_CONTEXT_DIR/security-policy-base64"
            )

        # Default snp_uvm_endorsements_file if not set
        if snp_uvm_endorsements_file is None:
            snp_uvm_endorsements_file = (
                "$UVM_SECURITY_CONTEXT_DIR/reference-info-base64"
            )

        # Default snp_endorsements_file if not set
        if snp_endorsements_file is None:
            snp_endorsements_file = "$UVM_SECURITY_CONTEXT_DIR/host-amd-cert-base64"

        # Validate consensus timers
        if (
            election_timeout_ms is not None
            and consensus_update_timeout_ms is not None
            and election_timeout_ms < 4 * consensus_update_timeout_ms
        ):
            LOG.error(
                f"Consensus message timeout ({consensus_update_timeout_ms}ms) is not significantly less than election timeout ({election_timeout_ms}ms). This may lead to many unintended elections"
            )

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
            t_env = Environment(loader=loader, autoescape=select_autoescape())
            t = t_env.get_template(self.TEMPLATE_CONFIGURATION_FILE)
            auto_dr_args = {}
            if sealed_ledger_secret_location is not None:
                auto_dr_args["sealed_ledger_secret_location"] = (
                    sealed_ledger_secret_location
                )
            if previous_sealed_ledger_secret_location is not None:
                auto_dr_args["previous_sealed_ledger_secret_location"] = (
                    previous_sealed_ledger_secret_location
                )

            output = t.render(
                start_type=start_type.name.title(),
                rpc_interfaces=infra.interfaces.HostSpec.to_json(
                    LocalRemote.make_host(host)
                ),
                node_certificate_file=self.pem,
                node_address_file=self.node_address_file,
                rpc_addresses_file=self.rpc_addresses_file,
                ledger_dir=self.ledger_dir_name,
                read_only_ledger_dirs=self.read_only_ledger_dirs_names,
                snapshots_dir=self.snapshots_dir_name,
                read_only_snapshots_dir=self.read_only_snapshots_dir_name,
                constitution=constitution,
                curve_id=curve_id.name.title(),
                host_log_level=log_level.title(),
                join_timer=f"{join_timer_s}s" if join_timer_s else None,
                signature_interval_duration=f"{sig_ms_interval}ms",
                jwt_key_refresh_interval=f"{jwt_key_refresh_interval_s}s",
                election_timeout=f"{election_timeout_ms}ms",
                message_timeout=f"{consensus_update_timeout_ms}ms",
                node_data_json_file=node_data_json_file,
                service_data_json_file=service_data_json_file,
                service_cert_file=service_cert_file,
                snp_endorsements_servers=snp_endorsements_servers_list,
                node_pid_file=node_pid_file,
                snp_security_context_directory_envvar=snp_security_context_directory_envvar,  # Ignored by current jinja, but passed for LTS compat
                ignore_first_sigterm=ignore_first_sigterm,
                node_address=LocalRemote.get_node_address(node_address),
                follow_redirect=follow_redirect,
                fetch_recent_snapshot=fetch_recent_snapshot,
                max_uncommitted_tx_count=max_uncommitted_tx_count,
                snp_security_policy_file=snp_security_policy_file,
                snp_uvm_endorsements_file=snp_uvm_endorsements_file,
                snp_endorsements_file=snp_endorsements_file,
                service_subject_name=service_subject_name,
                historical_cache_soft_limit=historical_cache_soft_limit,
                cose_signatures_issuer=cose_signatures_issuer,
                cose_signatures_subject=cose_signatures_subject,
                self_healing_open_cluster_identities=self_healing_open_cluster_identities,
                self_healing_open_identity=self_healing_open_identity,
                **auto_dr_args,
                **kwargs,
            )

            config_file_name = f"{self.local_node_id}.config.json"
            config_file = os.path.join(common_dir, config_file_name)
            exe_files += [config_file]

            with open(config_file, "w", encoding="utf-8") as f:
                # Parse and re-emit output to produce consistently formatted (indented) JSON.
                # This will also ensure the render produced valid JSON
                j = json.loads(output)

                # Enclave config removed from 7.x onwards.
                if major_version is not None and major_version < 7:
                    enclave_platform = infra.platform_detection.get_platform()
                    enclave_platform = (
                        "Virtual"
                        if enclave_platform.lower() == "virtual"
                        else enclave_platform.upper()
                    )
                    j["enclave"] = {
                        "type": "Release",
                        "platform": enclave_platform,
                    }

                json.dump(j, f, indent=2)

        exe_files += [self.BIN, enclave_file] + self.DEPS
        data_files += [self.ledger_dir] if self.ledger_dir else []
        data_files += [self.snapshots_dir] if self.snapshots_dir else []
        data_files += (
            [self.read_only_snapshots_dir] if self.read_only_snapshots_dir else []
        )
        if self.read_only_ledger_dirs_names:
            data_files.extend(
                [os.path.join(self.common_dir, f) for f in self.read_only_ledger_dirs]
            )

        # exe_files may be relative or absolute. The remote implementation should
        # copy (or symlink) to the target workspace, and then node will be able
        # to reference the destination file locally in the target workspace.
        bin_path = os.path.join(".", os.path.basename(self.BIN))

        # use the relative path to the config file so that it works on remotes too
        cmd = [
            bin_path,
            "--config",
            os.path.basename(config_file),
        ]

        v = (
            ccf._versionifier.to_python_version(version)
            if version is not None
            else None
        )
        if v is None or v >= Version("7.0.0.dev0"):
            cmd += [
                "--log-level",
                log_level,
            ]
        elif v >= Version("4.0.5"):
            cmd += [
                "--enclave-log-level",
                log_level,
            ]

        if v is not None and v >= Version("4.0.11") and v <= Version("7.0.0-dev1"):
            cmd += [
                "--enclave-file",
                self.enclave_file,
            ]

        if start_type == StartType.start:
            members_info = kwargs.get("members_info")
            if not members_info:
                raise ValueError("no members info for start node")
            for mi in members_info:
                data_files += [os.path.join(self.common_dir, mi["certificate_file"])]
                if mi["encryption_public_key_file"]:
                    data_files += [
                        os.path.join(self.common_dir, mi["encryption_public_key_file"])
                    ]
                if mi["data_json_file"]:
                    data_files += [os.path.join(self.common_dir, mi["data_json_file"])]

            for c in constitution:
                data_files += [os.path.join(self.common_dir, c)]

        if start_type == StartType.join:
            data_files += [os.path.join(self.common_dir, "service_cert.pem")]

        self.remote = LocalRemote(
            self.name,
            self.pub_host,
            exe_files,
            data_files,
            cmd,
            workspace,
            common_dir,
            env,
            pid_file=node_pid_file,
            binary_dir=binary_dir,
            host=host,
            label=label,
            local_node_id=local_node_id,
            version=version,
            node_container_image=node_container_image,
        )

    def setup(self, **kwargs):
        self.remote.setup(**kwargs)

    def start(self):
        self.remote.start()

    def suspend(self):
        return self.remote.suspend()

    def resume(self):
        self.remote.resume()

    def get_startup_files(self, dst_path, timeout=FILE_TIMEOUT_S):
        self.remote.get(self.pem, dst_path, timeout=REMOTE_STARTUP_TIMEOUT_S)
        if self.node_address_file is not None:
            self.remote.get(self.node_address_file, dst_path, timeout=timeout)
        if self.rpc_addresses_file is not None:
            self.remote.get(self.rpc_addresses_file, dst_path, timeout=timeout)
        if self.start_type in {StartType.start, StartType.recover}:
            self.remote.get("service_cert.pem", dst_path, timeout=timeout)

    def debug_node_cmd(self):
        return self.remote.debug_node_cmd()

    def sigterm(self):
        self.remote.sigterm()

    def sigkill(self):
        self.remote.sigkill()

    def log_stack_trace(self, timeout=20):
        self.remote.log_stack_trace(timeout=timeout)

    def stop(self):
        try:
            self.remote.stop()
        except Exception:
            LOG.exception("Failed to shut down {} cleanly".format(self.local_node_id))

    def check_done(self):
        return self.remote.check_done()

    def _resilient_copy(
        self,
        directory,
        pre_condition_func=lambda src_dir, _: True,
        target_name=None,
        max_retry_count=5,
    ):
        # It is possible that files (ledger, snapshots) are committed
        # while the copy is happening so retry a reasonable number of times.
        retry_count = 0
        while retry_count < max_retry_count:
            try:
                self.remote.get(
                    directory,
                    self.common_dir,
                    pre_condition_func=pre_condition_func,
                    target_name=target_name,
                )
                return
            except Exception as e:
                LOG.warning(f"Error copying file from {directory}: {e}. Retrying...")
                retry_count += 1
                time.sleep(0.1)

        raise TimeoutError(
            f"Error copying files from {directory} after {retry_count} retries"
        )

    def get_ledger(self, ledger_dir_name):
        self._resilient_copy(self.ledger_dir_name, target_name=ledger_dir_name)
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

    def get_committed_snapshots(self, pre_condition_func=lambda src_dir, _: True):
        self._resilient_copy(
            self.snapshots_dir_name, pre_condition_func=pre_condition_func
        )
        read_only_snapshots_dir = None
        if self.read_only_snapshots_dir_name:
            self._resilient_copy(self.read_only_snapshots_dir_name)
            read_only_snapshots_dir = os.path.join(
                self.common_dir, self.read_only_snapshots_dir_name
            )

        return (
            os.path.join(self.common_dir, self.snapshots_dir_name),
            read_only_snapshots_dir,
        )

    def log_path(self):
        return self.remote.out

    def ledger_paths(self):
        paths = [os.path.join(self.remote.root, self.ledger_dir_name)]
        for read_only_ledger_dir_name in self.read_only_ledger_dirs_names:
            paths += [os.path.join(self.remote.root, read_only_ledger_dir_name)]
        return [path for path in paths if os.path.exists(path)]

    def get_logs(self):
        return self.remote.get_logs()

    def get_main_ledger_dir(self):
        """
        Get the main ledger directory
        """
        return os.path.join(self.remote.root, self.ledger_dir_name)


class StartType(Enum):
    start = auto()
    join = auto()
    recover = auto()
