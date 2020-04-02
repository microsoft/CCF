# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from contextlib import contextmanager
from enum import Enum
import infra.remote
import infra.net
import infra.path
import infra.clients
import time
import json
import os

from loguru import logger as LOG


class NodeNetworkState(Enum):
    stopped = 0
    started = 1
    joined = 2


class NodeStatus(Enum):
    PENDING = 0
    TRUSTED = 1
    RETIRED = 2


class Node:
    def __init__(self, node_id, host, binary_dir=".", debug=False, perf=False):
        self.node_id = node_id
        self.binary_dir = binary_dir
        self.debug = debug
        self.perf = perf
        self.remote = None
        self.network_state = NodeNetworkState.stopped

        hosts, *port = host.split(":")
        self.host, *self.pubhost = hosts.split(",")
        self.rpc_port = port[0] if port else None

        if self.host == "localhost":
            self.host = infra.net.expand_localhost()
            self._set_ports(infra.net.probably_free_local_port)
            self.remote_impl = infra.remote.LocalRemote
        else:
            self._set_ports(infra.net.probably_free_remote_port)
            self.remote_impl = infra.remote.SSHRemote

        self.pubhost = self.pubhost[0] if self.pubhost else self.host

    def __hash__(self):
        return self.node_id

    def __eq__(self, other):
        return self.node_id == other.node_id

    def _set_ports(self, probably_free_function):
        if self.rpc_port is None:
            self.node_port, self.rpc_port = infra.net.two_different(
                probably_free_function, self.host
            )
        else:
            self.node_port = probably_free_function(self.host)

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
            None,
            members_info,
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
        **kwargs,
    ):
        self._start(
            infra.remote.StartType.join,
            lib_name,
            enclave_type,
            workspace,
            label,
            common_dir,
            target_rpc_address,
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
        members_info=None,
        **kwargs,
    ):
        """
        Creates a CCFRemote instance, sets it up (connects, creates the directory and ships over the files), and
        (optionally) starts the node by executing the appropriate command.
        If self.debug is set to True, it will not actually start up the node, but will prompt the user to do so manually
        Raises exception if failed to prepare or start the node
        :param lib_name: the enclave package to load
        :param enclave_type: default: debug. Choices: 'debug', 'virtual'
        :param workspace: directory where node is started
        :param label: label for this node (to differentiate nodes from different test runs)
        :return: void
        """
        lib_path = infra.path.build_lib_path(lib_name, enclave_type)
        self.common_dir = common_dir
        self.remote = infra.remote.CCFRemote(
            start_type,
            lib_path,
            str(self.node_id),
            self.host,
            self.pubhost,
            self.node_port,
            self.rpc_port,
            self.remote_impl,
            enclave_type,
            workspace,
            label,
            common_dir,
            target_rpc_address,
            members_info,
            binary_dir=self.binary_dir,
            **kwargs,
        )
        self.remote.setup()
        self.network_state = NodeNetworkState.started
        if self.debug:
            print("")
            phost = "localhost" if self.host.startswith("127.") else self.host
            print(
                "================= Please run the below command on "
                + phost
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
        LOG.info("Remote {} started".format(self.node_id))

    def stop(self):
        if self.remote and self.network_state is not NodeNetworkState.stopped:
            self.network_state = NodeNetworkState.stopped
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
            with self.node_client(connection_timeout=timeout) as nc:
                rep = nc.get("getCommit")
                assert (
                    rep.error is None and rep.result is not None
                ), f"An error occured after node {self.node_id} joined the network"
        except infra.clients.CCFConnectionException as e:
            raise TimeoutError(f"Node {self.node_id} failed to join the network")

    def get_ledger(self):
        return self.remote.get_ledger()

    def get_sealed_secrets(self):
        with open(self.remote.get_sealed_secrets()) as s:
            return json.load(s)

    def user_client(self, user_id=0, **kwargs):
        return infra.clients.client(
            self.host,
            self.rpc_port,
            cert=os.path.join(self.common_dir, f"user{user_id}_cert.pem"),
            key=os.path.join(self.common_dir, f"user{user_id}_privk.pem"),
            ca=os.path.join(self.common_dir, "networkcert.pem"),
            description=f"node {self.node_id} (user {user_id})",
            prefix="users",
            binary_dir=self.binary_dir,
            **kwargs,
        )

    def node_client(self, timeout=3, **kwargs):
        return infra.clients.client(
            self.host,
            self.rpc_port,
            cert=None,
            key=None,
            ca=os.path.join(self.common_dir, "networkcert.pem"),
            description=f"node {self.node_id} (node)",
            prefix="nodes",
            binary_dir=self.binary_dir,
            **kwargs,
        )

    def member_client(self, member_id=0, **kwargs):
        return infra.clients.client(
            self.host,
            self.rpc_port,
            cert=os.path.join(self.common_dir, f"member{member_id}_cert.pem"),
            key=os.path.join(self.common_dir, f"member{member_id}_privk.pem"),
            ca=os.path.join(self.common_dir, "networkcert.pem"),
            description=f"node {self.node_id} (member {member_id})",
            prefix="members",
            binary_dir=self.binary_dir,
            **kwargs,
        )

    def suspend(self):
        self.remote.suspend()

    def resume(self):
        self.remote.resume()


@contextmanager
def node(node_id, host, binary_directory, debug=False, perf=False, pdb=False):
    """
    Context manager for Node class.
    :param node_id: unique ID of node
    :param binary_directory: the directory where CCF's binaries are located
    :param host: node's hostname
    :param debug: default: False. If set, node will not start (user is prompted to start them manually)
    :param perf: default: False. If set, node will run under perf record
    :return: a Node instance that can be used to build a CCF network
    """
    node = Node(
        node_id=node_id, host=host, binary_dir=binary_directory, debug=debug, perf=perf
    )
    try:
        yield node
    except Exception:
        if pdb:
            import pdb

            pdb.set_trace()
        else:
            raise
    finally:
        node.stop()
