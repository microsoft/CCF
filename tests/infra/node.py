# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from contextlib import contextmanager, closing
from enum import Enum, auto
import infra.crypto
import infra.remote
import infra.remote_shim
from datetime import datetime, timedelta
import infra.net
import infra.path
import infra.interfaces
import infra.clients
import ccf.ledger
import os
import socket
import re
import ipaddress
import ssl
import copy
import json

# pylint: disable=import-error, no-name-in-module
from setuptools.extern.packaging.version import Version  # type: ignore

from loguru import logger as LOG

BASE_NODE_CLIENT_HOST = "127.100.0.0"


class NodeNetworkState(Enum):
    stopped = auto()
    started = auto()
    joined = auto()


class State(Enum):
    UNINITIALIZED = "Uninitialized"
    INITIALIZED = "Initialized"
    PENDING = "Pending"
    PART_OF_PUBLIC_NETWORK = "PartOfPublicNetwork"
    PART_OF_NETWORK = "PartOfNetwork"
    READING_PUBLIC_LEDGER = "ReadingPublicLedger"
    READING_PRIVATE_LEDGER = "ReadingPrivateLedger"
    VERIFYING_SNAPSHOT = "VerifyingSnapshot"


def is_addr_local(host, port):
    with closing(socket.socket()) as s:
        try:
            s.bind((host, port or 0))
            return True
        except OSError:
            return False


def is_file_committed(file_name):
    return ".committed" in file_name


def is_ledger_file(file_name):
    return file_name.startswith("ledger_")


def get_committed_ledger_end_seqno(file_name):
    if not is_ledger_file(file_name) or not is_file_committed(file_name):
        raise ValueError(f"{file_name} ledger file is not a committed ledger file")
    return int(re.findall(r"\d+", file_name)[1])


def get_snapshot_seqnos(file_name):
    # Returns the tuple (snapshot_seqno, evidence_seqno)
    seqnos = re.findall(r"\d+", file_name)
    return int(seqnos[0]), int(seqnos[1])


def strip_version(full_version):
    if full_version is None:
        return None
    dash_offset = 1 if full_version.startswith("ccf-") else 0
    return full_version.split("-")[dash_offset]


def version_rc(full_version):
    if full_version is None:
        return (None, 0)
    tokens = full_version.split("-")
    rc_tkn = tokens[2] if len(tokens) > 2 else None
    return (int(rc_tkn[2:]), len(tokens)) if rc_tkn else (None, 0)


class Node:
    # Default to using httpx
    curl = False

    def __init__(
        self,
        local_node_id,
        host,
        binary_dir=".",
        library_dir=".",
        debug=False,
        perf=False,
        node_port=0,
        version=None,
        node_data_json_file=None,
    ):
        self.local_node_id = local_node_id
        self.binary_dir = binary_dir
        self.library_dir = library_dir
        self.debug = debug
        self.perf = perf
        self.remote = None
        self.network_state = NodeNetworkState.stopped
        self.common_dir = None
        self.suspended = False
        self.node_id = None
        self.node_client_host = None
        # Note: Do not modify host argument as it may be passed to multiple
        # nodes or networks
        self.host = copy.deepcopy(host)
        self.version = version
        self.major_version = (
            Version(strip_version(self.version)).release[0]
            if self.version is not None
            else None
        )
        self.consensus = None
        self.certificate_valid_from = None
        self.certificate_validity_days = None
        self.initial_node_data_json_file = node_data_json_file

        if os.getenv("CONTAINER_NODES"):
            self.remote_shim = infra.remote_shim.DockerShim
        else:
            self.remote_shim = infra.remote_shim.PassThroughShim

        if isinstance(self.host, str):
            self.host = infra.interfaces.HostSpec.from_str(self.host)

        for interface_name, rpc_interface in self.host.rpc_interfaces.items():
            # Main RPC interface determines remote implementation
            if interface_name == infra.interfaces.PRIMARY_RPC_INTERFACE:
                if rpc_interface.protocol == "local":
                    self.remote_impl = infra.remote.LocalRemote
                    # Node client address does not currently work with DockerShim
                    if self.remote_shim != infra.remote_shim.DockerShim:
                        if not self.major_version or self.major_version > 1:
                            self.node_client_host = str(
                                ipaddress.ip_address(BASE_NODE_CLIENT_HOST)
                                + self.local_node_id
                            )
                elif rpc_interface.protocol == "ssh":
                    self.remote_impl = infra.remote.SSHRemote
                else:
                    assert (
                        False
                    ), f"{rpc_interface.protocol} is not 'local://' or 'ssh://'"

            if rpc_interface.host == "localhost":
                rpc_interface.host = infra.net.expand_localhost()

            if rpc_interface.public_host is None:
                rpc_interface.public_host = rpc_interface.host
                rpc_interface.public_port = rpc_interface.port

            # Default node address host to same host as main RPC interface
            if interface_name == infra.interfaces.PRIMARY_RPC_INTERFACE:
                self.n2n_interface = infra.interfaces.Interface(
                    host=rpc_interface.host, port=node_port
                )

    def __hash__(self):
        return self.local_node_id

    def __eq__(self, other):
        return self.local_node_id == other.local_node_id

    def start(
        self,
        lib_name,
        enclave_type,
        workspace,
        label,
        common_dir,
        members_info,
        **kwargs,
    ):
        self._start(
            infra.remote.StartType.start,
            lib_name,
            enclave_type,
            workspace,
            label,
            common_dir,
            members_info=members_info,
            **kwargs,
        )
        self.network_state = NodeNetworkState.joined

    def join(
        self,
        lib_name,
        enclave_type,
        workspace,
        label,
        common_dir,
        **kwargs,
    ):
        self._start(
            infra.remote.StartType.join,
            lib_name,
            enclave_type,
            workspace,
            label,
            common_dir,
            **kwargs,
        )

    def recover(self, lib_name, enclave_type, workspace, label, common_dir, **kwargs):
        self._start(
            infra.remote.StartType.recover,
            lib_name,
            enclave_type,
            workspace,
            label,
            common_dir,
            **kwargs,
        )
        self.network_state = NodeNetworkState.joined

    def get_consensus(self):
        return self.consensus

    def _start(
        self,
        start_type,
        lib_name,
        enclave_type,
        workspace,
        label,
        common_dir,
        members_info=None,
        **kwargs,
    ):
        """
        Creates a CCFRemote instance, sets it up (connects, creates the directory
        and ships over the files), and (optionally) starts the node by executing
        the appropriate command.
        If self.debug is set, it will not actually start up the node, but will
        prompt the user to do so manually.
        """
        lib_path = infra.path.build_lib_path(
            lib_name, enclave_type, library_dir=self.library_dir
        )
        self.common_dir = common_dir
        members_info = members_info or []

        self.remote = self.remote_shim(
            start_type,
            lib_path,
            enclave_type,
            self.remote_impl,
            workspace,
            common_dir,
            binary_dir=self.binary_dir,
            label=label,
            local_node_id=self.local_node_id,
            host=self.host,
            node_address=infra.interfaces.make_address(
                self.n2n_interface.host, self.n2n_interface.port
            ),
            node_address_port=self.n2n_interface.port,
            node_client_interface=self.node_client_host,
            members_info=members_info,
            version=self.version,
            major_version=self.major_version,
            node_data_json_file=self.initial_node_data_json_file,
            **kwargs,
        )
        self.remote.setup()
        self.network_state = NodeNetworkState.started
        if self.debug:
            with open("/tmp/vscode-gdb.sh", "a", encoding="utf-8") as f:
                f.write(f"if [ $1 -eq {self.remote.local_node_id} ]; then\n")
                f.write(f"cd {self.remote.remote.root}\n")
                f.write(f"exec {' '.join(self.remote.remote.cmd)}\n")
                f.write("fi\n")

            print("")
            print(
                "================= Please run the below command on "
                + self.get_public_rpc_host()
                + " and press enter to continue ================="
            )
            print("")
            print(self.remote.debug_node_cmd())
            print("")
            input("Press Enter to continue...")
        else:
            if self.perf:
                self.remote.set_perf()
            self.remote.start()

        try:
            file_timeout = kwargs.get("file_timeout")
            self.remote.get_startup_files(
                self.common_dir, timeout=file_timeout or infra.remote.FILE_TIMEOUT
            )
        except Exception as e:
            LOG.exception(e)
            self.remote.get_logs(tail_lines_len=None)
            raise

        self.consensus = kwargs.get("consensus")

        with open(
            os.path.join(self.common_dir, self.remote.pem), encoding="utf-8"
        ) as f:
            self.node_id = infra.crypto.compute_public_key_der_hash_hex_from_pem(
                f.read()
            )

        self._read_ports()
        self.certificate_validity_days = kwargs.get("initial_node_cert_validity_days")
        LOG.info(f"Node {self.local_node_id} started: {self.node_id}")

    def _resolve_address(self, address_file_path, interfaces):
        with open(address_file_path, "r", encoding="utf-8") as f:
            addresses = json.load(f)

        for interface_name, resolved_address in addresses.items():
            host, port = infra.interfaces.split_address(resolved_address)
            interface = interfaces[interface_name]
            if self.remote_shim != infra.remote_shim.DockerShim:
                assert (
                    host == interface.host
                ), f"Unexpected change in address from {interface.host} to {host} in {address_file_path}"
            if interface.port != 0:
                assert (
                    port == interface.port
                ), f"Unexpected change in node port from {interface.port} to {port} in {address_file_path}"
            interface.port = port

    def _read_ports(self):
        if self.major_version is None or self.major_version > 1:
            if self.remote.node_address_file is not None:
                node_address_file = os.path.join(
                    self.common_dir, self.remote.node_address_file
                )
                self._resolve_address(
                    node_address_file,
                    {infra.interfaces.NODE_TO_NODE_INTERFACE_NAME: self.n2n_interface},
                )

            if self.remote.rpc_addresses_file is not None:
                rpc_address_file = os.path.join(
                    self.common_dir, self.remote.rpc_addresses_file
                )
                self._resolve_address(rpc_address_file, self.host.rpc_interfaces)
                #  In the infra, public RPC port is always the same as local RPC port
                for _, interface in self.host.rpc_interfaces.items():
                    interface.public_port = interface.port
        else:
            # Legacy 1.x nodes
            if self.remote.node_address_file is not None:
                node_address_file = os.path.join(
                    self.common_dir, self.remote.node_address_file
                )
                with open(node_address_file, "r", encoding="utf-8") as f:
                    node_host, node_port = f.read().splitlines()
                    node_port = int(node_port)
                    if self.remote_shim != infra.remote_shim.DockerShim:
                        assert (
                            node_host == self.n2n_interface.host
                        ), f"Unexpected change in node address from {self.n2n_interface.host} to {node_host}"
                    if self.n2n_interface.port != 0:
                        assert (
                            node_port == self.n2n_interface.port
                        ), f"Unexpected change in node port from {self.n2n_interface.port} to {node_port}"
                    self.n2n_interface.port = node_port

            if self.remote.rpc_addresses_file is not None:
                rpc_address_file = os.path.join(
                    self.common_dir, self.remote.rpc_addresses_file
                )
                with open(rpc_address_file, "r", encoding="utf-8") as f:
                    lines = f.read().splitlines()
                    it = [iter(lines)] * 2
                for (rpc_host, rpc_port), (_, rpc_interface) in zip(
                    zip(*it), self.host.rpc_interfaces.items()
                ):
                    rpc_port = int(rpc_port)
                    if self.remote_shim != infra.remote_shim.DockerShim:
                        assert (
                            rpc_host == rpc_interface.host
                        ), f"Unexpected change in RPC address from {rpc_interface.host} to {rpc_host}"
                    if rpc_interface.port != 0:
                        assert (
                            rpc_port == rpc_interface.port
                        ), f"Unexpected change in RPC port from {rpc_interface.port} to {rpc_port}"
                    rpc_interface.port = int(rpc_port)
                    # In the infra, public RPC port is always the same as local RPC port
                    rpc_interface.public_port = rpc_interface.port

    def stop(self, *args, **kwargs):
        if self.remote and self.network_state is not NodeNetworkState.stopped:
            if self.suspended:
                self.resume()
            self.network_state = NodeNetworkState.stopped
            LOG.info(f"Stopping node {self.local_node_id}")
            return self.remote.stop(*args, **kwargs)
        return [], []

    def is_stopped(self):
        return self.network_state == NodeNetworkState.stopped

    def is_joined(self):
        return self.network_state == NodeNetworkState.joined

    def wait_for_node_to_join(self, timeout=3):
        """
        This function can be used to check that a node has successfully
        joined a network and that it is part of the consensus.
        """
        # Until the node has joined, the SSL handshake will fail as the node
        # is not yet endorsed by the service certificate

        try:
            with self.client(connection_timeout=timeout) as nc:
                rep = nc.get("/node/commit")
                assert (
                    rep.status_code == 200
                ), f"An error occured after node {self.local_node_id} joined the network: {rep.body}"
                self.network_state = infra.node.NodeNetworkState.joined
        except infra.clients.CCFConnectionException as e:
            raise TimeoutError(
                f"Node {self.local_node_id} failed to join the network"
            ) from e

    def get_ledger_public_tables_at(self, seqno):
        ledger = ccf.ledger.Ledger(self.remote.ledger_paths())
        assert ledger.last_committed_chunk_range[1] >= seqno
        tx = ledger.get_transaction(seqno)
        return tx.get_public_domain().get_tables()

    def get_ledger_public_state_at(self, seqno):
        ledger = ccf.ledger.Ledger(self.remote.ledger_paths())
        assert ledger.last_committed_chunk_range[1] >= seqno
        return ledger.get_latest_public_state()

    def get_ledger(self):
        """
        Triage committed and un-committed (i.e. current) ledger files
        """
        main_ledger_dir, read_only_ledger_dirs = self.remote.get_ledger(
            f"{self.local_node_id}.ledger"
        )

        current_ledger_dir = os.path.join(
            self.common_dir, f"{self.local_node_id}.ledger.current"
        )
        committed_ledger_dir = os.path.join(
            self.common_dir, f"{self.local_node_id}.ledger.committed"
        )
        infra.path.create_dir(current_ledger_dir)
        infra.path.create_dir(committed_ledger_dir)

        for f in os.listdir(main_ledger_dir):
            infra.path.copy_dir(
                os.path.join(main_ledger_dir, f),
                committed_ledger_dir if is_file_committed(f) else current_ledger_dir,
            )

        for ro_dir in read_only_ledger_dirs:
            for f in os.listdir(ro_dir):
                # Uncommitted ledger files from r/o ledger directory are ignored by CCF
                if is_file_committed(f):
                    infra.path.copy_dir(os.path.join(ro_dir, f), committed_ledger_dir)

        return current_ledger_dir, [committed_ledger_dir]

    def get_snapshots(self):
        return self.remote.get_snapshots()

    def get_committed_snapshots(self, pre_condition_func=lambda src_dir, _: True):
        return self.remote.get_committed_snapshots(pre_condition_func)

    def identity(self, name=None):
        if name is not None:
            return infra.clients.Identity(
                os.path.join(self.common_dir, f"{name}_privk.pem"),
                os.path.join(self.common_dir, f"{name}_cert.pem"),
                name,
            )

    def session_auth(self, name=None):
        return {"session_auth": self.identity(name)}

    def signing_auth(self, name=None):
        return {"signing_auth": self.identity(name)}

    def get_public_rpc_host(self):
        return self.remote.get_host()

    def get_public_rpc_port(
        self, interface_name=infra.interfaces.PRIMARY_RPC_INTERFACE
    ):
        return self.host.rpc_interfaces[interface_name].port

    def session_ca(self, self_signed_ok):
        if self_signed_ok:
            return {"ca": ""}
        else:
            return {"ca": os.path.join(self.common_dir, "service_cert.pem")}

    def client(
        self,
        identity=None,
        signing_identity=None,
        interface_name=infra.interfaces.PRIMARY_RPC_INTERFACE,
        self_signed_ok=False,
        **kwargs,
    ):
        if self.network_state == NodeNetworkState.stopped:
            raise RuntimeError(
                f"Cannot create client for node {self.local_node_id} as node is stopped"
            )

        akwargs = self.session_ca(self_signed_ok)
        akwargs.update(self.session_auth(identity))
        akwargs.update(self.signing_auth(signing_identity))
        akwargs[
            "description"
        ] = f"[{self.local_node_id}|{identity or ''}|{signing_identity or ''}]"
        akwargs.update(kwargs)

        if self.curl:
            akwargs["curl"] = True

        try:
            rpc_interface = self.host.rpc_interfaces[interface_name]
        except KeyError:
            LOG.error(
                f'Cannot create client on interface "{interface_name}" - available interfaces: {self.host.rpc_interfaces.keys()}'
            )
            raise

        return infra.clients.client(
            rpc_interface.public_host, rpc_interface.public_port, **akwargs
        )

    def get_tls_certificate_pem(
        self, interface_name=infra.interfaces.PRIMARY_RPC_INTERFACE
    ):
        return ssl.get_server_certificate(
            (
                self.get_public_rpc_host(),
                self.get_public_rpc_port(interface_name=interface_name),
            )
        )

    def suspend(self):
        assert not self.suspended
        self.suspended = True
        self.remote.suspend()
        LOG.info(f"Node {self.local_node_id} suspended...")

    def resume(self):
        assert self.suspended
        self.suspended = False
        self.remote.resume()
        LOG.info(f"Node {self.local_node_id} has resumed from suspension.")

    def set_certificate_validity_period(self, valid_from, validity_period_days):
        self.certificate_valid_from = valid_from
        self.certificate_validity_days = validity_period_days

    def verify_certificate_validity_period(
        self,
        expected_validity_period_days=None,
        ignore_proposal_valid_from=False,
        interface_name=infra.interfaces.PRIMARY_RPC_INTERFACE,
    ):
        node_tls_cert = self.get_tls_certificate_pem(interface_name=interface_name)
        assert (
            infra.crypto.compute_public_key_der_hash_hex_from_pem(node_tls_cert)
            == self.node_id
        )

        valid_from, valid_to = infra.crypto.get_validity_period_from_pem_cert(
            node_tls_cert
        )

        if ignore_proposal_valid_from or self.certificate_valid_from is None:
            # If the node certificate has not been renewed, assume that certificate has
            # been issued within this test run
            expected_valid_from = datetime.utcnow() - timedelta(hours=1)
            if valid_from < expected_valid_from:
                raise ValueError(
                    f'Node {self.local_node_id} certificate is too old: valid from "{valid_from}" older than expected "{expected_valid_from}"'
                )
        else:
            if (
                infra.crypto.datetime_to_X509time(valid_from)
                != self.certificate_valid_from
            ):
                raise ValueError(
                    f'Validity period for node {self.local_node_id} certificate is not as expected: valid from "{infra.crypto.datetime_to_X509time(valid_from)}", but expected "{self.certificate_valid_from}"'
                )

        # Note: CCF substracts one second from validity period since x509 specifies
        # that validity dates are inclusive.
        expected_valid_to = valid_from + timedelta(
            days=expected_validity_period_days or self.certificate_validity_days,
            seconds=-1,
        )
        if valid_to != expected_valid_to:
            raise ValueError(
                f'Validity period for node {self.local_node_id} certiticate is not as expected: valid to "{valid_to}" but expected "{expected_valid_to}"'
            )

        validity_period = valid_to - valid_from + timedelta(seconds=1)
        LOG.info(
            f"Certificate validity period for node {self.local_node_id} successfully verified: {valid_from} - {valid_to} (for {validity_period})"
        )

    def check_log_for_error_message(self, msg):
        if self.remote is not None:
            with open(self.remote.remote.out, encoding="utf-8") as f:
                for line in f:
                    if msg in line:
                        return True
        return False

    def version_after(self, version):
        rc, _ = version_rc(version)
        if rc is None or self.version is None:
            return True
        self_rc, self_num_rc_tkns = version_rc(self.version)
        ver = Version(strip_version(version))
        self_ver = Version(strip_version(self.version))
        return self_ver > ver or (
            self_ver == ver
            and (
                not self_rc or self_rc > rc or (self_rc == rc and self_num_rc_tkns > 3)
            )
        )


@contextmanager
def node(
    local_node_id,
    host,
    binary_directory,
    library_directory,
    debug=False,
    perf=False,
    pdb=False,
):
    """
    Context manager for Node class.
    :param local_node_id: infra-specific unique ID
    :param binary_directory: the directory where CCF's binaries are located
    :param library_directory: the directory where CCF's libraries are located
    :param host: node's hostname
    :param debug: default: False. If set, node will not start (user is prompted to start them manually)
    :param perf: default: False. If set, node will run under perf record
    :return: a Node instance that can be used to build a CCF network
    """
    this_node = Node(
        local_node_id=local_node_id,
        host=host,
        binary_dir=binary_directory,
        library_dir=library_directory,
        debug=debug,
        perf=perf,
    )
    try:
        yield this_node
    except Exception:
        if pdb:
            import pdb

            # pylint: disable=forgotten-debug-statement
            pdb.set_trace()
        else:
            raise
    finally:
        this_node.stop()
