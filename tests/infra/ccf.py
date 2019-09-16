# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import json
import os
import time
import logging
from contextlib import contextmanager
from glob import glob
from enum import Enum
import infra.jsonrpc
import infra.remote
import infra.path
import infra.net
import infra.proc
import array
import re

from loguru import logger as LOG

logging.getLogger("paramiko").setLevel(logging.WARNING)


class NodeNetworkState(Enum):
    stopped = 0
    started = 1
    joined = 2


class ServiceStatus(Enum):
    OPENING = 1
    OPEN = 2
    CLOSED = 3


@contextmanager
def network(
    hosts,
    build_directory,
    dbg_nodes=[],
    perf_nodes=[],
    create_nodes=True,
    node_offset=0,
    pdb=False,
):
    """
    Context manager for Network class.
    :param hosts: a list of hostnames (localhost or remote hostnames)
    :param build_directory: the build directory
    :param dbg_nodes: default: []. List of node id's that will not start (user is prompted to start them manually)
    :param perf_nodes: default: []. List of node ids that will run under perf record
    :param create_nodes: default: True. If set to false it turns off the automatic node creation
    :return: a Network instance that can be used to create/access nodes, handle the genesis state (add members, create
    node.json), and stop all the nodes that belong to the network
    """
    with infra.path.working_dir(build_directory):
        net = Network(
            hosts=hosts,
            dbg_nodes=dbg_nodes,
            perf_nodes=perf_nodes,
            create_nodes=create_nodes,
            node_offset=node_offset,
        )
        try:
            yield net
        except Exception:
            if pdb:
                import pdb

                pdb.set_trace()
            else:
                raise
        finally:
            net.stop_all_nodes()


# TODO: This function should only be part of the Checker class once the
# memberclient is no longer used.
def wait_for_global_commit(
    management_client, commit_index, term, mksign=False, timeout=2
):
    """
    Given a client to a CCF network and a commit_index/term pair, this function
    waits for this specific commit index to be globally committed by the
    network in this term.
    A TimeoutError exception is raised if the commit index is not globally
    committed within the given timeout.
    """
    # Waiting for a global commit can significantly slow down tests as
    # signatures take some time to be emitted and globally committed.
    # Forcing a signature accelerates this process for common operations
    # (e.g. governance proposals)
    if mksign:
        management_client.rpc("mkSign", params={})

    for i in range(timeout * 10):
        r = management_client.rpc("getCommit", {"commit": commit_index})
        if r.global_commit >= commit_index and r.result["term"] == term:
            return
        time.sleep(0.1)
    raise TimeoutError("Timed out waiting for commit")


class Network:
    node_args_to_forward = [
        "enclave_type",
        "host_log_level",
        "ignore_quote",
        "sig_max_tx",
        "sig_max_ms",
        "election_timeout",
        "memory_reserve_startup",
        "notify_server",
        "json_log_path",
        "gov_script",
        "app_script",
    ]

    # Maximum delay (seconds) for updates to propagate from the primary to backups
    replication_delay = 30

    def __init__(
        self, hosts, dbg_nodes=None, perf_nodes=None, create_nodes=True, node_offset=0
    ):
        self.nodes = []
        self.members = []
        self.hosts = hosts
        self.net_cert = []
        if create_nodes:
            for local_node_id, host in enumerate(hosts):
                local_node_id_ = local_node_id + node_offset
                self.create_node(
                    local_node_id_,
                    host,
                    debug=str(local_node_id_) in (dbg_nodes or []),
                    perf=str(local_node_id_) in (perf_nodes or []),
                )

    def start_and_join(self, args):
        # TODO: The node that starts should not necessarily be node 0
        cmd = ["rm", "-f"] + glob("member*.pem")
        infra.proc.ccall(*cmd)

        hosts = self.hosts or ["localhost"] * number_of_local_nodes()

        if not args.package:
            raise ValueError("A package name must be specified.")

        LOG.info("Starting nodes on {}".format(hosts))

        self.create_members([1, 2, 3])
        initial_users = [1, 2, 3]
        self.create_users(initial_users)

        if args.app_script:
            infra.proc.ccall("cp", args.app_script, args.build_dir).check_returncode()
        if args.gov_script:
            infra.proc.ccall("cp", args.gov_script, args.build_dir).check_returncode()
        LOG.info("Lua scripts copied")

        primary = None
        for i, node in enumerate(self.nodes):
            dict_args = vars(args)
            forwarded_args = {
                arg: dict_args[arg] for arg in Network.node_args_to_forward
            }
            try:
                if i == 0:
                    node.start(
                        lib_name=args.package,
                        workspace=args.workspace,
                        label=args.label,
                        members_certs="member*_cert.pem",
                        **forwarded_args,
                    )
                else:
                    primary, _ = self.find_primary()
                    node.join(
                        lib_name=args.package,
                        workspace=args.workspace,
                        label=args.label,
                        target_rpc_address=f"{primary.host}:{primary.rpc_port}",
                        **forwarded_args,
                    )
                node.wait_for_node_to_join()
                node.network_state = NodeNetworkState.joined
            except Exception:
                LOG.exception("Failed to start node {}".format(i))
                raise
        LOG.info("All remotes started")

        if primary is None:
            primary = self.nodes[0]

        self.wait_for_all_nodes_to_catch_up(primary)
        LOG.success("All nodes joined network")

        self.add_users(primary, initial_users)
        LOG.info("Initial set of users added")

        self.open_network(primary)
        LOG.success("***** Network is now open *****")

        return primary, self.nodes[1:]

    def start_in_recovery(self, args, ledger_file, sealed_secrets):
        hosts = self.hosts or ["localhost"] * number_of_local_nodes()

        if not args.package:
            raise ValueError("A package name must be specified.")

        if args.app_script:
            infra.proc.ccall("cp", args.app_script, args.build_dir).check_returncode()
        if args.gov_script:
            infra.proc.ccall("cp", args.gov_script, args.build_dir).check_returncode()
        LOG.info("Lua scripts copied")

        LOG.info("Starting nodes on {}".format(hosts))

        forwarded_args = {
            arg: getattr(args, arg) for arg in infra.ccf.Network.node_args_to_forward
        }

        # In recovery, the primary is automatically the node that started
        primary = self.nodes[0]

        try:
            # Only start the first node. In practice, one might decide to
            # start all nodes with their own ledger to find out which ledger
            # is the longest. Then, all nodes except the ones with the
            # longest ledger are stopped and restarted in "join".
            self.nodes[0].recover(
                lib_name=args.package,
                ledger_file=ledger_file,
                sealed_secrets=sealed_secrets,
                workspace=args.workspace,
                label=args.label,
                **forwarded_args,
            )
            self.nodes[0].network_state = NodeNetworkState.joined
        except Exception:
            LOG.exception("Failed to start recovery node {}".format(i))
            raise

        for node in self.nodes:
            if node != primary:
                node.join(
                    lib_name=args.package,
                    workspace=args.workspace,
                    label=args.label,
                    target_rpc_address=f"{primary.host}:{primary.rpc_port}",
                    **forwarded_args,
                )
                node.wait_for_node_to_join()
                node.network_state = NodeNetworkState.joined

        self.wait_for_all_nodes_to_catch_up(primary)
        self.check_for_service(primary, status=ServiceStatus.OPENING)

        LOG.success("All nodes joined recovered public network")

        return primary, self.nodes[1:]

    def check_for_service(self, node, status=ServiceStatus.OPEN):
        """
        Check via the member frontend of the given node that the certificate
        associated with current CCF service signing key has been recorded in
        the KV store with the appropriate status.
        """
        with node.member_client() as c:
            rep = c.do(
                "query",
                {
                    "text": """tables = ...
                    return tables["ccf.service"]:get(0)"""
                },
            )
            current_status = rep.result["status"].decode()
            current_cert = array.array("B", rep.result["cert"]).tobytes()

            expected_cert = open("networkcert.pem", "rb").read()
            assert (
                current_cert == expected_cert
            ), "Current service certificate did not match with networkcert.pem"
            assert (
                current_status == status.name
            ), f"Service status {current_status} (expected {status.name})"

    def create_node(self, local_node_id, host, debug=False, perf=False):
        node = Node(local_node_id, host, debug, perf)
        self.nodes.append(node)
        return node

    def remove_last_node(self):
        last_node = self.nodes.pop()

    def create_and_add_node(self, lib_name, args):
        forwarded_args = {
            arg: getattr(args, arg) for arg in infra.ccf.Network.node_args_to_forward
        }
        local_node_id = self.get_next_local_node_id()
        new_node = self.create_node(local_node_id, "localhost")

        primary, _ = self.find_primary()
        new_node.join(
            lib_name=lib_name,
            workspace=args.workspace,
            label=args.label,
            target_rpc_address=f"{primary.host}:{primary.rpc_port}",
            **forwarded_args,
        )

        try:
            new_node.wait_for_node_to_join()
        except RuntimeError:
            LOG.error(f"New node {local_node_id} failed to join the network")
            self.nodes.remove(new_node)
            return None

        new_node.network_state = NodeNetworkState.joined
        self.wait_for_all_nodes_to_catch_up(primary)
        LOG.success(f"New node {local_node_id} joined the network")
        return new_node

    def create_members(self, members):
        self.members.extend(members)
        members = ["member{}".format(m) for m in members]
        for m in members:
            infra.proc.ccall("./keygenerator", "--name={}".format(m)).check_returncode()

    def create_users(self, users):
        users = ["user{}".format(u) for u in users]
        for u in users:
            infra.proc.ccall("./keygenerator", "--name={}".format(u)).check_returncode()

    # TODO: The following governance functions should be moved to their own class
    # See https://github.com/microsoft/CCF/issues/364
    def member_client_rpc_as_json(self, member_id, remote_node, *args):
        if remote_node is None:
            remote_node = self.find_primary()[0]

        result = infra.proc.ccall(
            "./memberclient",
            f"--cert=member{member_id}_cert.pem",
            f"--privk=member{member_id}_privk.pem",
            f"--rpc-address={remote_node.host}:{remote_node.rpc_port}",
            "--ca=networkcert.pem",
            *args,
        )
        j_result = json.loads(result.stdout)
        return j_result

    def propose(self, member_id, remote_node, proposal, *args):
        j_result = self.member_client_rpc_as_json(
            member_id, remote_node, proposal, *args
        )

        if j_result.get("error") is not None:
            self.remove_last_node()
            return (False, j_result["error"])

        return (True, j_result["result"])

    def vote_using_majority(self, remote_node, proposal_id):
        # There is no need to stop after n / 2 + 1 members have voted,
        # but this could prove to be useful in detecting errors
        # related to the voting mechanism
        member_count = int(len(self.members) / 2 + 1)
        for i, member in enumerate(self.members):
            if i >= member_count:
                break
            res = self.vote(member, remote_node, proposal_id, True)
            assert res[0]
            if res[1]:
                break

        assert res
        return res[1]

    def vote(self, member_id, remote_node, proposal_id, accept, force_unsigned=False):
        j_result = self.member_client_rpc_as_json(
            member_id,
            remote_node,
            "vote",
            f"--proposal-id={proposal_id}",
            "--accept" if accept else "--reject",
            "--force-unsigned" if force_unsigned else "",
        )
        if j_result.get("error") is not None:
            return (False, j_result["error"])

        # If the proposal was accepted, wait for it to be globally committed
        # This is particularly useful for the open network proposal to wait
        # until the global hook on the SERVICE table is triggered
        if j_result["result"]:
            with remote_node.management_client() as mc:
                wait_for_global_commit(mc, j_result["commit"], j_result["term"], True)

        return (True, j_result["result"])

    def propose_retire_node(self, member_id, remote_node, node_id):
        return self.propose(
            member_id, remote_node, "retire_node", f"--node-id={node_id}"
        )

    def retire_node(self, remote_node, node_id):
        member_id = 1
        result = self.propose_retire_node(member_id, remote_node, node_id)
        result = self.vote_using_majority(remote_node, result[1]["id"])

        with remote_node.member_client() as c:
            id = c.request("read", {"table": "ccf.nodes", "key": node_id})
            assert c.response(id).result["status"].decode() == "RETIRED"

    def propose_add_member(self, member_id, remote_node, new_member_cert):
        return self.propose(
            member_id, remote_node, "add_member", f"--member-cert={new_member_cert}"
        )

    def open_network(self, node):
        """
        Assuming a network in state OPENING, this functions creates a new
        proposal and make members vote to transition the network to state
        OPEN.
        """
        result = self.propose(1, node, "open_network")
        self.vote_using_majority(node, result[1]["id"])
        self.check_for_service(node)

    def add_users(self, node, users):
        for u in users:
            result = self.propose(1, node, "add_user", f"--user-cert=user{u}_cert.pem")
            result = self.vote_using_majority(node, result[1]["id"])

    def stop_all_nodes(self):
        for node in self.nodes:
            node.stop()
        LOG.info("All remotes stopped...")

    def get_members(self):
        return self.members

    def get_running_nodes(self):
        return [node for node in self.nodes if node.is_stopped() is not True]

    def get_node_by_id(self, node_id):
        return next((node for node in self.nodes if node.node_id == node_id), None)

    def find_primary(self):
        """
        Find the identity of the primary in the network and return its identity
        and the current term.
        """
        primary_id = None
        term = None

        for node in self.get_running_nodes():
            with node.management_client() as c:
                id = c.request("getPrimaryInfo", {})
                res = c.response(id)
                if res.error is None:
                    primary_id = res.result["primary_id"]
                    term = res.term
                    break
                else:
                    assert (
                        res.error["code"] == infra.jsonrpc.ErrorCode.TX_PRIMARY_UNKNOWN
                    ), "RPC error code is not TX_NOT_PRIMARY"
        assert primary_id is not None, "No primary found"

        return (self.get_node_by_id(primary_id), term)

    def wait_for_all_nodes_to_catch_up(self, primary, timeout=3):
        """
        Wait for all nodes to have joined the network and globally replicated
        all transactions executed on the primary (including the transactions
        which added the nodes).
        """
        with primary.management_client() as c:
            res = c.do("getCommit", {})
            local_commit_leader = res.commit
            term_leader = res.term

        for _ in range(timeout):
            joined_nodes = 0
            for node in self.get_running_nodes():
                with node.management_client() as c:
                    id = c.request("getCommit", {})
                    resp = c.response(id)
                    if resp.error is not None:
                        # Node may not have joined the network yet, try again
                        break
                    if (
                        resp.global_commit >= local_commit_leader
                        and resp.result["term"] == term_leader
                    ):
                        joined_nodes += 1
            if joined_nodes == len(self.get_running_nodes()):
                break
            time.sleep(1)
        assert joined_nodes == len(
            self.get_running_nodes()
        ), f"Only {joined_nodes} (out of {self.get_running_nodes()}) nodes have joined the network"

    def wait_for_node_commit_sync(self, timeout=3):
        """
        Wait for commit level to get in sync on all nodes. This is expected to
        happen once CFTR has been established, in the absence of new transactions.
        """
        for _ in range(timeout):
            commits = []
            for node in (node for node in self.nodes if node.is_joined()):
                with node.management_client() as c:
                    id = c.request("getCommit", {})
                    commits.append(c.response(id).commit)
            if [commits[0]] * len(commits) == commits:
                break
            time.sleep(1)
        assert [commits[0]] * len(commits) == commits, "All nodes at the same commit"

    def get_next_local_node_id(self):
        if len(self.nodes):
            return self.nodes[-1].local_node_id + 1
        return 0


class Checker:
    def __init__(self, management_client=None, notification_queue=None):
        self.management_client = management_client
        self.notification_queue = notification_queue

    def __call__(self, rpc_result, result=None, error=None, timeout=2):
        if error is not None:
            if callable(error):
                assert error(rpc_result.error), rpc_result.error
            else:
                assert rpc_result.error == error, "Expected {}, got {}".format(
                    error, rpc_result.error
                )
            return

        if result is not None:
            if callable(result):
                assert result(rpc_result.result), rpc_result.result
            else:
                assert rpc_result.result == result, "Expected {}, got {}".format(
                    result, rpc_result.result
                )

            if self.management_client:
                wait_for_global_commit(
                    self.management_client, rpc_result.commit, rpc_result.term
                )

            if self.notification_queue:
                for i in range(timeout * 10):
                    for q in list(self.notification_queue.queue):
                        if json.loads(q)["commit"] >= rpc_result.commit:
                            return
                    time.sleep(0.5)
                raise TimeoutError("Timed out waiting for notification")


@contextmanager
def node(local_node_id, host, build_directory, debug=False, perf=False, pdb=False):
    """
    Context manager for Node class.
    :param local_node_id: unique ID of node - relevant only for the python environment
    :param build_directory: the build directory
    :param host: node's hostname
    :param debug: default: False. If set, node will not start (user is prompted to start them manually)
    :param perf: default: False. If set, node will run under perf record
    :return: a Node instance that can be used to build a CCF network
    """
    with infra.path.working_dir(build_directory):
        node = Node(local_node_id=local_node_id, host=host, debug=debug, perf=perf)
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


class Node:
    def __init__(self, local_node_id, host, debug=False, perf=False):
        self.node_id = local_node_id
        self.local_node_id = local_node_id
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

    def start(self, lib_name, enclave_type, workspace, label, members_certs, **kwargs):
        self._start(
            infra.remote.StartType.new,
            lib_name,
            enclave_type,
            workspace,
            label,
            None,
            members_certs,
            **kwargs,
        )

    def join(
        self, lib_name, enclave_type, workspace, label, target_rpc_address, **kwargs
    ):
        self._start(
            infra.remote.StartType.join,
            lib_name,
            enclave_type,
            workspace,
            label,
            target_rpc_address,
            **kwargs,
        )

    def recover(self, lib_name, enclave_type, workspace, label, **kwargs):
        self._start(
            infra.remote.StartType.recover,
            lib_name,
            enclave_type,
            workspace,
            label,
            **kwargs,
        )

    def _start(
        self,
        start_type,
        lib_name,
        enclave_type,
        workspace,
        label,
        target_rpc_address=None,
        members_certs=None,
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
        self.remote = infra.remote.CCFRemote(
            start_type,
            lib_path,
            str(self.local_node_id),
            self.host,
            self.pubhost,
            self.node_port,
            self.rpc_port,
            self.remote_impl,
            enclave_type,
            workspace,
            label,
            target_rpc_address,
            members_certs,
            **kwargs,
        )
        self.remote.setup()
        LOG.info("Remote {} started".format(self.local_node_id))
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
        self.remote.get_startup_files()

    def stop(self):
        if self.remote:
            self.remote.stop()
            self.network_state = NodeNetworkState.stopped

    def is_stopped(self):
        return self.network_state == NodeNetworkState.stopped

    def is_joined(self):
        return self.network_state == NodeNetworkState.joined

    def wait_for_node_to_join(self, timeout=3):
        """
        This function can be used to check that a node has successfully
        joined a network and that it is part of the consensus.
        """
        for _ in range(timeout):
            with self.management_client() as mc:
                rep = mc.do("getCommit", {})
                if rep.error == None and rep.result is not None:
                    return
            time.sleep(1)
        raise RuntimeError(f"Node {self.node_id} failed to join the network")

    def get_sealed_secrets(self):
        return self.remote.get_sealed_secrets()

    def user_client(self, format="msgpack", user_id=1, **kwargs):
        return infra.jsonrpc.client(
            self.host,
            self.rpc_port,
            cert="user{}_cert.pem".format(user_id),
            key="user{}_privk.pem".format(user_id),
            cafile="networkcert.pem",
            description="node {} (user)".format(self.local_node_id),
            format=format,
            **kwargs,
        )

    def management_client(self, **kwargs):
        return infra.jsonrpc.client(
            self.host,
            self.rpc_port,
            "management",
            cert=None,
            key=None,
            cafile="{}.pem".format(self.local_node_id),
            description="node {} (mgmt)".format(self.local_node_id),
            **kwargs,
        )

    def member_client(self, member_id=1, **kwargs):
        return infra.jsonrpc.client(
            self.host,
            self.rpc_port,
            "members",
            cert="member{}_cert.pem".format(member_id),
            key="member{}_privk.pem".format(member_id),
            cafile="networkcert.pem",
            description="node {} (member)".format(self.local_node_id),
            **kwargs,
        )
