# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from contextlib import contextmanager, closing
from enum import Enum, auto
import infra.crypto
import infra.remote
import infra.net
import infra.path
import ccf.clients
import ccf.ledger
import os
import socket
import re
import ipaddress

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


class Node:
    def __init__(
        self,
        local_node_id,
        host,
        binary_dir=".",
        library_dir=".",
        debug=False,
        perf=False,
        node_port=None,
        version=None,
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
        self.interfaces = []
        self.version = version

        if host.protocol == "local":
            self.remote_impl = infra.remote.LocalRemote
            if not version or version > 1:
                self.node_client_host = str(
                    ipaddress.ip_address(BASE_NODE_CLIENT_HOST) + self.local_node_id
                )
        elif host.protocol == "ssh":
            self.remote_impl = infra.remote.SSHRemote
        else:
            assert False, f"{host} does not start with 'local://' or 'ssh://'"

        host_ = host.rpchost
        self.host, *port = host_.split(":")
        self.rpc_port = int(port[0]) if port else None
        if self.host == "localhost":
            self.host = infra.net.expand_localhost()

        pubhost_ = host.public_rpchost
        if pubhost_:
            self.pubhost, *pubport = pubhost_[0].split(":")
            self.pubport = int(pubport[0]) if pubport else self.rpc_port
        else:
            self.pubhost = self.host
            self.pubport = self.rpc_port
        self.node_port = node_port

        self.max_open_sessions = host.max_open_sessions
        self.max_open_sessions_hard = host.max_open_sessions_hard
        self.additional_raw_node_args = host.additional_raw_node_args

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
            infra.remote.StartType.new,
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
        target_rpc_address,
        snapshot_dir,
        **kwargs,
    ):
        self._start(
            infra.remote.StartType.join,
            lib_name,
            enclave_type,
            workspace,
            label,
            common_dir,
            target_rpc_address=target_rpc_address,
            snapshot_dir=snapshot_dir,
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

    def _start(
        self,
        start_type,
        lib_name,
        enclave_type,
        workspace,
        label,
        common_dir,
        target_rpc_address=None,
        snapshot_dir=None,
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
        if self.max_open_sessions:
            kwargs["max_open_sessions"] = self.max_open_sessions
        if self.max_open_sessions_hard:
            kwargs["max_open_sessions_hard"] = self.max_open_sessions_hard
        self.common_dir = common_dir
        self.remote = infra.remote.CCFRemote(
            start_type,
            lib_path,
            self.local_node_id,
            self.host,
            self.pubhost,
            self.node_port,
            self.rpc_port,
            self.node_client_host,
            self.remote_impl,
            enclave_type,
            workspace,
            label,
            common_dir,
            target_rpc_address=target_rpc_address,
            members_info=members_info,
            snapshot_dir=snapshot_dir,
            binary_dir=self.binary_dir,
            additional_raw_node_args=self.additional_raw_node_args,
            **kwargs,
        )
        self.remote.setup()
        self.network_state = NodeNetworkState.started
        if self.debug:
            with open("/tmp/vscode-gdb.sh", "a") as f:
                f.write(f"if [ $1 -eq {self.remote.local_node_id} ]; then\n")
                f.write(f"cd {self.remote.remote.root}\n")
                f.write(f"{' '.join(self.remote.remote.cmd)}\n")
                f.write("fi\n")

            print("")
            print(
                "================= Please run the below command on "
                + self.host
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
        self.remote.get_startup_files(self.common_dir)

        if kwargs.get("consensus") == "cft":
            with open(os.path.join(self.common_dir, f"{self.local_node_id}.pem")) as f:
                self.node_id = infra.crypto.compute_public_key_der_hash_hex_from_pem(
                    f.read()
                )
        else:
            # BFT consensus should deterministically compute the primary id from the
            # consensus view, so node ids are monotonic in this case
            self.node_id = "{:0>64}".format(self.local_node_id)

        self._read_ports()
        LOG.info(f"Node {self.local_node_id} started: {self.node_id}")

    def _read_ports(self):
        node_address_path = os.path.join(self.common_dir, self.remote.node_address_path)
        with open(node_address_path, "r") as f:
            node_host, node_port = f.read().splitlines()
            node_port = int(node_port)
            assert (
                node_host == self.host
            ), f"Unexpected change in node address from {self.host} to {node_host}"
            if self.node_port is not None:
                assert (
                    node_port == self.node_port
                ), f"Unexpected change in node port from {self.node_port} to {node_port}"
            self.node_port = node_port

        rpc_address_path = os.path.join(self.common_dir, self.remote.rpc_address_path)
        with open(rpc_address_path, "r") as f:
            lines = f.read().splitlines()
            it = [iter(lines)] * 2
            for i, (rpc_host, rpc_port) in enumerate(zip(*it)):
                rpc_port = int(rpc_port)
                if i == 0:
                    assert (
                        rpc_host == self.host
                    ), f"Unexpected change in RPC address from {self.host} to {rpc_host}"
                    if self.rpc_port is not None:
                        assert (
                            rpc_port == self.rpc_port
                        ), f"Unexpected change in RPC port from {self.rpc_port} to {rpc_port}"
                    self.rpc_port = rpc_port
                    if self.pubport is None:
                        self.pubport = self.rpc_port
                self.interfaces.append((rpc_host, rpc_port))

    def stop(self):
        if self.remote and self.network_state is not NodeNetworkState.stopped:
            if self.suspended:
                self.resume()
            self.network_state = NodeNetworkState.stopped
            LOG.info(f"Stopping node {self.local_node_id}")
            return self.remote.stop()
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
        # is not yet endorsed by the network certificate

        try:
            with self.client(connection_timeout=timeout) as nc:
                rep = nc.get("/node/commit")
                assert (
                    rep.status_code == 200
                ), f"An error occured after node {self.local_node_id} joined the network: {rep.body}"
                self.network_state = infra.node.NodeNetworkState.joined
        except ccf.clients.CCFConnectionException as e:
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

    def get_ledger(self, include_read_only_dirs=False):
        """
        Triage committed and un-committed (i.e. current) ledger files
        """
        main_ledger_dir, read_only_ledger_dirs = self.remote.get_ledger(
            f"{self.local_node_id}.ledger", include_read_only_dirs
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

        return current_ledger_dir, committed_ledger_dir

    def get_snapshots(self):
        return self.remote.get_snapshots()

    def get_committed_snapshots(self, pre_condition_func=lambda src_dir, _: True):
        return self.remote.get_committed_snapshots(pre_condition_func)

    def identity(self, name=None):
        if name is not None:
            return ccf.clients.Identity(
                os.path.join(self.common_dir, f"{name}_privk.pem"),
                os.path.join(self.common_dir, f"{name}_cert.pem"),
                name,
            )

    def session_auth(self, name=None):
        return {
            "session_auth": self.identity(name),
            "ca": os.path.join(self.common_dir, "networkcert.pem"),
        }

    def signing_auth(self, name=None):
        return {
            "signing_auth": self.identity(name),
        }

    def client(
        self, identity=None, signing_identity=None, interface_idx=None, **kwargs
    ):
        if self.network_state == NodeNetworkState.stopped:
            raise RuntimeError(
                f"Cannot create client for node {self.local_node_id} as node is stopped"
            )
        akwargs = self.session_auth(identity)
        akwargs.update(self.signing_auth(signing_identity))
        akwargs[
            "description"
        ] = f"[{self.local_node_id}|{identity or ''}|{signing_identity or ''}]"
        akwargs.update(kwargs)
        if interface_idx is None:
            return ccf.clients.client(self.pubhost, self.pubport, **akwargs)
        else:
            try:
                host, port = self.interfaces[interface_idx]
            except IndexError:
                LOG.error(
                    f"Cannot create client on interface {interface_idx} - this node only has {len(self.interfaces)} interfaces"
                )
                raise
            return ccf.clients.client(host, port, **akwargs)

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

            pdb.set_trace()
        else:
            raise
    finally:
        this_node.stop()
