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
import ssl
import random

from loguru import logger as LOG

logging.getLogger("paramiko").setLevel(logging.WARNING)


class NodeNetworkState(Enum):
    stopped = 0
    started = 1
    joined = 2


class NodeStatus(Enum):
    PENDING = 0
    TRUSTED = 1
    RETIRED = 2


class ServiceStatus(Enum):
    OPENING = 1
    OPEN = 2
    CLOSED = 3


@contextmanager
def network(
    hosts, build_directory, dbg_nodes=[], perf_nodes=[], pdb=False,
):
    """
    Context manager for Network class.
    :param hosts: a list of hostnames (localhost or remote hostnames)
    :param build_directory: the build directory
    :param dbg_nodes: default: []. List of node id's that will not start (user is prompted to start them manually)
    :param perf_nodes: default: []. List of node ids that will run under perf record
    :return: a Network instance that can be used to create/access nodes, handle the genesis state (add members, create
    node.json), and stop all the nodes that belong to the network
    """
    with infra.path.working_dir(build_directory):
        net = Network(hosts=hosts, dbg_nodes=dbg_nodes, perf_nodes=perf_nodes)
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
def wait_for_global_commit(node_client, commit_index, term, mksign=False, timeout=3):
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
        node_client.rpc("mkSign", params={})

    for i in range(timeout * 10):
        r = node_client.rpc("getCommit", {"commit": commit_index})
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
    ]

    # Maximum delay (seconds) for updates to propagate from the primary to backups
    replication_delay = 30

    def __init__(self, hosts, dbg_nodes=None, perf_nodes=None, existing_network=None):
        if existing_network is None:
            self.members = []
            self.node_offset = 0
        else:
            self.members = list(existing_network.members)
            # When creating a new network from an existing one (e.g. for recovery),
            # the node id of the nodes of the new network should start from the node
            # id of the existing network, so that new nodes id match the ones in the
            # nodes KV table
            self.node_offset = (
                len(existing_network.nodes) + existing_network.node_offset
            )

        self.nodes = []
        self.hosts = hosts
        self.status = ServiceStatus.CLOSED
        self.dbg_nodes = dbg_nodes
        self.perf_nodes = perf_nodes

        for host in hosts:
            self.create_node(host)

    def _start_all_nodes(
        self, args, recovery=False, ledger_file=None, sealed_secrets=None
    ):

        hosts = self.hosts or ["localhost"] * number_of_local_nodes()

        if not args.package:
            raise ValueError("A package name must be specified.")

        self.status = ServiceStatus.OPENING
        LOG.info("Opening CCF service on {}".format(hosts))

        forwarded_args = {
            arg: getattr(args, arg) for arg in infra.ccf.Network.node_args_to_forward
        }

        for i, node in enumerate(self.nodes):
            dict_args = vars(args)
            forwarded_args = {
                arg: dict_args[arg] for arg in Network.node_args_to_forward
            }
            try:
                if i == 0:
                    if not recovery:
                        node.start(
                            lib_name=args.package,
                            workspace=args.workspace,
                            label=args.label,
                            members_certs=self.get_members_certs(),
                            **forwarded_args,
                        )
                    else:
                        node.recover(
                            lib_name=args.package,
                            ledger_file=ledger_file,
                            sealed_secrets=sealed_secrets,
                            workspace=args.workspace,
                            label=args.label,
                            **forwarded_args,
                        )
                else:
                    self._add_node(node, args.package, args)
            except Exception:
                LOG.exception("Failed to start node {}".format(i))
                raise
        LOG.info("All remotes started")

        primary, term = self.find_primary()
        self.check_for_service(primary, status=ServiceStatus.OPENING)

        return primary

    def start_and_join(self, args):
        """
        Starts a CCF network.
        :param args: command line arguments to configure the CCF nodes.
        :param open_network: If false, only the nodes are started.
        """
        # TODO: The node that starts should not necessarily be node 0
        cmd = ["rm", "-f"] + glob("member*.pem")
        infra.proc.ccall(*cmd)

        self.create_members([1, 2, 3])
        self.initial_users = [1, 2, 3]
        self.create_users(self.initial_users)

        if args.gov_script:
            infra.proc.ccall("cp", args.gov_script, args.build_dir).check_returncode()
        LOG.info("Lua scripts copied")

        primary = self._start_all_nodes(args)

        if not args.pbft:
            self.wait_for_all_nodes_to_catch_up(primary)
        LOG.success("All nodes joined network")

        if args.app_script:
            infra.proc.ccall("cp", args.app_script, args.build_dir).check_returncode()
            self.set_lua_app(primary, args.app_script)

        self.add_users(primary, self.initial_users)
        LOG.info("Initial set of users added")

        self.open_network(args, primary)
        LOG.success("***** Network is now open *****")

    def start_in_recovery(self, args, ledger_file, sealed_secrets):
        primary = self._start_all_nodes(
            args, recovery=True, ledger_file=ledger_file, sealed_secrets=sealed_secrets
        )
        self.wait_for_all_nodes_to_catch_up(primary)
        LOG.success("All nodes joined recovered public network")

    def create_node(self, host):
        node_id = self.get_next_local_node_id()
        debug = (
            (str(node_id) in self.dbg_nodes) if self.dbg_nodes is not None else False
        )
        perf = (
            (str(node_id) in self.perf_nodes) if self.perf_nodes is not None else False
        )
        node = Node(node_id, host, debug, perf)
        self.nodes.append(node)
        return node

    def _add_node(self, node, lib_name, args, target_node=None):
        forwarded_args = {
            arg: getattr(args, arg) for arg in infra.ccf.Network.node_args_to_forward
        }

        # Contact primary if no target node is set
        if target_node is None:
            target_node, _ = self.find_primary()

        node.join(
            lib_name=lib_name,
            workspace=args.workspace,
            label=args.label,
            target_rpc_address=f"{target_node.host}:{target_node.rpc_port}",
            **forwarded_args,
        )

        # If the network is opening, node are trusted without consortium approval
        if self.status == ServiceStatus.OPENING and not args.pbft:
            try:
                node.wait_for_node_to_join()
            except TimeoutError:
                LOG.error(f"New node {node.node_id} failed to join the network")
                raise
            node.network_state = NodeNetworkState.joined

    def _wait_for_node_to_exist_in_store(
        self, remote_node, node_id, node_status=None, timeout=20
    ):
        exists = False
        for _ in range(timeout):
            if self._check_node_exists(remote_node, node_id, node_status):
                exists = True
                break
            time.sleep(1)
        if not exists:
            raise TimeoutError(
                f"Node {node_id} has not yet been recorded in the store"
                + getattr(node_status, f" with status {node_status.name}", "")
            )

    def create_and_add_pending_node(self, lib_name, host, args, target_node=None):
        """
        Create a new node and add it to the network. Note that the new node
        still needs to be trusted by members to complete the join protocol.
        """
        new_node = self.create_node(host)
        self._add_node(new_node, lib_name, args, target_node)
        primary, term = self.find_primary()
        try:
            self._wait_for_node_to_exist_in_store(
                primary,
                new_node.node_id,
                (
                    NodeStatus.PENDING
                    if self.status == ServiceStatus.OPEN
                    else NodeStatus.TRUSTED
                ),
            )
        except TimeoutError:
            # The node can be safely discarded since it has not been
            # attributed a unique node_id by CCF
            LOG.error(f"New pending node {new_node.node_id} failed to join the network")
            new_node.stop()
            self.nodes.remove(new_node)
            return None

        return new_node

    def create_and_trust_node(self, lib_name, host, args, target_node=None):
        """
        Create a new node, add it to the network and let members vote to trust
        it so that it becomes part of the consensus protocol.
        """
        new_node = self.create_and_add_pending_node(lib_name, host, args, target_node)
        if new_node is None:
            return None

        primary, term = self.find_primary()
        try:
            if self.status is ServiceStatus.OPEN:
                self.trust_node(primary, new_node.node_id)
            if not args.pbft:
                new_node.wait_for_node_to_join()
        except (ValueError, TimeoutError):
            LOG.error(f"New trusted node {new_node.node_id} failed to join the network")
            new_node.stop()
            return None

        new_node.network_state = NodeNetworkState.joined
        if not args.pbft:
            self.wait_for_all_nodes_to_catch_up(primary)

        return new_node

    def create_members(self, members):
        self.members.extend(members)
        members = [f"member{m}" for m in members]
        for m in members:
            infra.proc.ccall("./keygenerator", "--name={}".format(m)).check_returncode()

    def get_members_certs(self):
        members_certs = [f"member{m}_cert.pem" for m in self.members]
        return members_certs

    def create_users(self, users):
        users = ["user{}".format(u) for u in users]
        for u in users:
            infra.proc.ccall("./keygenerator", "--name={}".format(u)).check_returncode()

    def wait_for_state(self, node, state, timeout=3):
        for _ in range(timeout):
            try:
                with node.node_client(format="json") as c:
                    id = c.request("getSignedIndex", {})
                    r = c.response(id).result
                    if r["state"] == state:
                        break
            except ConnectionRefusedError:
                pass
            time.sleep(1)
        else:
            raise TimeoutError(
                f"Timed out waiting for public ledger to be read on node {node.node_id}"
            )

    # TODO: The following governance functions should be moved to their own class
    # See https://github.com/microsoft/CCF/issues/364
    def check_for_service(self, node, status=ServiceStatus.OPEN):
        """
        Check via the member frontend of the given node that the certificate
        associated with current CCF service signing key has been recorded in
        the KV store with the appropriate status.
        """
        with node.member_client(format="json") as c:
            rep = c.do(
                "query",
                {
                    "text": """tables = ...
                    return tables["ccf.service"]:get(0)"""
                },
            )
            current_status = rep.result["status"]
            current_cert = array.array("B", rep.result["cert"]).tobytes()

            expected_cert = open("networkcert.pem", "rb").read()
            assert (
                current_cert == expected_cert
            ), "Current service certificate did not match with networkcert.pem"
            assert (
                current_status == status.name
            ), f"Service status {current_status} (expected {status.name})"
        self.status = status

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

    def propose(self, member_id, remote_node, script=None, params=None, *args):
        if os.getenv("HTTP"):
            with remote_node.member_client() as mc:
                r = mc.rpc("propose", {"parameter": params, "script": {"text": script}})
                return (True, r.result)
        else:
            j_result = self.member_client_rpc_as_json(member_id, remote_node, *args)

            if j_result.get("error") is not None:
                return (False, j_result["error"])

            return (True, j_result["result"])

    def vote_using_majority(
        self, remote_node, proposal_id, should_wait_for_global_commit=True
    ):
        # There is no need to stop after n / 2 + 1 members have voted,
        # but this could prove to be useful in detecting errors
        # related to the voting mechanism
        majority_count = int(len(self.members) / 2 + 1)
        for i, member in enumerate(self.members):
            if i >= majority_count:
                break
            res = self.vote(
                member,
                remote_node,
                proposal_id,
                True,
                False,
                should_wait_for_global_commit,
            )
            assert res[0]
            if res[1]:
                break

        assert res
        return res[1]

    def vote(
        self,
        member_id,
        remote_node,
        proposal_id,
        accept,
        force_unsigned=False,
        should_wait_for_global_commit=True,
    ):
        if os.getenv("HTTP"):
            script = """
            tables, changes = ...
            return true
            """
            with remote_node.member_client(member_id) as mc:
                r = mc.rpc(
                    "vote", {"ballot": {"text": script}, "id": proposal_id}, signed=True
                )
            return (True, r.result)
        else:
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
        if j_result["result"] and should_wait_for_global_commit:
            with remote_node.node_client(member_id) as mc:
                wait_for_global_commit(mc, j_result["commit"], j_result["term"], True)

        return (True, j_result["result"])

    def propose_retire_node(self, member_id, remote_node, node_id):
        return self.propose(
            member_id, remote_node, None, None, "retire_node", f"--node-id={node_id}"
        )

    def retire_node(self, node_to_retire):
        member_id = 1
        primary, term = self.find_primary()
        result = self.propose_retire_node(member_id, primary, node_to_retire.node_id)
        self.vote_using_majority(primary, result[1]["id"])

        with primary.member_client() as c:
            id = c.request(
                "read", {"table": "ccf.nodes", "key": node_to_retire.node_id}
            )
            assert c.response(id).result["status"].decode() == NodeStatus.RETIRED.name

    def propose_trust_node(self, member_id, remote_node, node_id):
        return self.propose(
            member_id, remote_node, None, None, "trust_node", f"--node-id={node_id}"
        )

    def _check_node_exists(self, remote_node, node_id, node_status=None):
        with remote_node.member_client() as c:
            rep = c.do("read", {"table": "ccf.nodes", "key": node_id})

            if rep.error is not None or (
                node_status and rep.result["status"].decode() != node_status.name
            ):
                return False

        return True

    def trust_node(self, remote_node, node_id):
        if not self._check_node_exists(remote_node, node_id, NodeStatus.PENDING):
            raise ValueError(f"Node {node_id} does not exist in state PENDING")

        member_id = 1
        result = self.propose_trust_node(member_id, remote_node, node_id)
        self.vote_using_majority(remote_node, result[1]["id"])

        if not self._check_node_exists(remote_node, node_id, NodeStatus.TRUSTED):
            raise ValueError(f"Node {node_id} does not exist in state TRUSTED")

    def propose_add_member(self, member_id, remote_node, new_member_cert):
        return self.propose(
            member_id,
            remote_node,
            None,
            None,
            "add_member",
            f"--member-cert={new_member_cert}",
        )

    def open_network(self, args, node):
        """
        Assuming a network in state OPENING, this functions creates a new
        proposal and make members vote to transition the network to state
        OPEN.
        """
        script = None
        if os.getenv("HTTP"):
            script = """
            tables = ...
            return Calls:call("open_network")
            """
        result = self.propose(1, node, script, None, "open_network")
        self.vote_using_majority(node, result[1]["id"], not args.pbft)

        self.check_for_service(node)

    def add_users(self, node, users):
        if os.getenv("HTTP"):
            with node.member_client() as mc:
                for u in users:
                    user_cert = []
                    with open(f"user{u}_cert.pem") as cert:
                        user_cert = [ord(c) for c in cert.read()]
                    script = """
                    tables, user_cert = ...
                    return Calls:call("new_user", user_cert)
                    """
                    r = mc.rpc(
                        "propose", {"parameter": user_cert, "script": {"text": script}}
                    )
                    with node.member_client(2) as mc2:
                        script = """
                        tables, changes = ...
                        return true
                        """
                        r = mc2.rpc(
                            "vote",
                            {"ballot": {"text": script}, "id": r.result["id"]},
                            signed=True,
                        )
        else:
            for u in users:
                result = self.propose(
                    1, node, None, None, "add_user", f"--user-cert=user{u}_cert.pem"
                )
                self.vote_using_majority(node, result[1]["id"])

    def set_lua_app(self, node, app_script):
        result = self.propose(
            1, node, None, None, "set_lua_app", f"--lua-app-file={app_script}"
        )
        self.vote_using_majority(node, result[1]["id"])

    def accept_recovery(self, node, sealed_secrets):
        result = self.propose(
            1, node, None, None, "accept_recovery", f"--sealed-secrets={sealed_secrets}"
        )
        self.vote_using_majority(node, result[1]["id"])

    def wait_for_all_nodes_to_be_trusted(self, timeout=3):
        primary, term = self.find_primary()
        for n in self.nodes:
            self._wait_for_node_to_exist_in_store(
                primary, n.node_id, NodeStatus.TRUSTED
            )

    def stop_all_nodes(self):
        for node in self.nodes:
            node.stop()
        LOG.info("All remotes stopped...")

    def get_members(self):
        return self.members

    def get_joined_nodes(self):
        return [node for node in self.nodes if node.is_joined()]

    def get_node_by_id(self, node_id):
        return next((node for node in self.nodes if node.node_id == node_id), None)

    def find_primary(self, timeout=3):
        """
        Find the identity of the primary in the network and return its identity
        and the current term.
        """
        primary_id = None
        term = None

        for _ in range(timeout):
            for node in self.get_joined_nodes():
                with node.node_client() as c:
                    id = c.request("getPrimaryInfo", {})
                    res = c.response(id)
                    if res.error is None:
                        primary_id = res.result["primary_id"]
                        term = res.term
                        break
                    else:
                        assert (
                            res.error["code"]
                            == infra.jsonrpc.ErrorCode.TX_PRIMARY_UNKNOWN
                        ), "RPC error code is not TX_NOT_PRIMARY"
            if primary_id is not None:
                break
            time.sleep(1)

        assert primary_id is not None, "No primary found"
        return (self.get_node_by_id(primary_id), term)

    def find_backups(self, primary=None, timeout=3):
        if primary is None:
            primary, term = self.find_primary(timeout)
        return [n for n in self.get_joined_nodes() if n != primary]

    def find_any_backup(self, primary=None, timeout=3):
        return random.choice(self.find_backups(primary=primary, timeout=timeout))

    def find_nodes(self, timeout=3):
        primary, term = self.find_primary(timeout)
        backups = self.find_backups(primary=primary, timeout=timeout)
        return primary, backups

    def find_primary_and_any_backup(self, timeout=3):
        primary, backups = self.find_nodes(timeout)
        backup = random.choice(backups)
        return primary, backup

    def wait_for_all_nodes_to_catch_up(self, primary, timeout=3):
        """
        Wait for all nodes to have joined the network and globally replicated
        all transactions executed on the primary (including the transactions
        which added the nodes).
        """
        with primary.node_client() as c:
            res = c.do("getCommit", {})
            local_commit_leader = res.commit
            term_leader = res.term

        for _ in range(timeout):
            caught_up_nodes = []
            for node in self.get_joined_nodes():
                with node.node_client() as c:
                    id = c.request("getCommit", {})
                    resp = c.response(id)
                    if resp.error is not None:
                        # Node may not have joined the network yet, try again
                        break
                    if (
                        resp.global_commit >= local_commit_leader
                        and resp.result["term"] == term_leader
                    ):
                        caught_up_nodes.append(node)
            if len(caught_up_nodes) == len(self.get_joined_nodes()):
                break
            time.sleep(1)
        assert len(caught_up_nodes) == len(
            self.get_joined_nodes()
        ), f"Only {len(caught_up_nodes)} (out of {len(self.get_joined_nodes())}) nodes have joined the network"

    def wait_for_node_commit_sync(self, timeout=3):
        """
        Wait for commit level to get in sync on all nodes. This is expected to
        happen once CFTR has been established, in the absence of new transactions.
        """
        for _ in range(timeout):
            commits = []
            for node in self.get_joined_nodes():
                with node.node_client() as c:
                    id = c.request("getCommit", {})
                    commits.append(c.response(id).commit)
            if [commits[0]] * len(commits) == commits:
                break
            time.sleep(1)
        assert [commits[0]] * len(commits) == commits, "All nodes at the same commit"

    def get_next_local_node_id(self):
        if len(self.nodes):
            return self.nodes[-1].node_id + 1
        return self.node_offset


class Checker:
    def __init__(self, node_client=None, notification_queue=None):
        self.node_client = node_client
        self.notification_queue = notification_queue
        self.notified_commit = 0

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

            if self.node_client:
                wait_for_global_commit(
                    self.node_client, rpc_result.commit, rpc_result.term
                )

            if self.notification_queue:
                for i in range(timeout * 10):
                    while self.notification_queue.not_empty:
                        notification = self.notification_queue.get()
                        n = json.loads(notification)["commit"]
                        assert (
                            n > self.notified_commit
                        ), f"Received notification of commit {n} after commit {self.notified_commit}"
                        self.notified_commit = n
                        if n >= rpc_result.commit:
                            return
                    time.sleep(0.5)
                raise TimeoutError("Timed out waiting for notification")


@contextmanager
def node(node_id, host, build_directory, debug=False, perf=False, pdb=False):
    """
    Context manager for Node class.
    :param node_id: unique ID of node
    :param build_directory: the build directory
    :param host: node's hostname
    :param debug: default: False. If set, node will not start (user is prompted to start them manually)
    :param perf: default: False. If set, node will run under perf record
    :return: a Node instance that can be used to build a CCF network
    """
    with infra.path.working_dir(build_directory):
        node = Node(node_id=node_id, host=host, debug=debug, perf=perf)
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
    def __init__(self, node_id, host, debug=False, perf=False):
        self.node_id = node_id
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
        self.network_state = NodeNetworkState.joined

    def suspend(self):
        self.remote.suspend()

    def resume(self):
        self.remote.resume()

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
        self.network_state = NodeNetworkState.joined

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
            str(self.node_id),
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
        LOG.info("Remote {} started".format(self.node_id))

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
            with self.node_client() as mc:
                rep = mc.do("getCommit", {})
                if rep.error == None and rep.result is not None:
                    return
            time.sleep(1)
        raise TimeoutError(f"Node {self.node_id} failed to join the network")

    def get_sealed_secrets(self):
        return self.remote.get_sealed_secrets()

    def user_client(self, format="msgpack", user_id=1, **kwargs):
        return infra.jsonrpc.client(
            self.host,
            self.rpc_port,
            cert="user{}_cert.pem".format(user_id),
            key="user{}_privk.pem".format(user_id),
            cafile="networkcert.pem",
            description="node {} (user)".format(self.node_id),
            format=format,
            prefix="users",
            **kwargs,
        )

    def node_client(self, timeout=3, **kwargs):
        return infra.jsonrpc.client(
            self.host,
            self.rpc_port,
            "nodes",
            cert=None,
            key=None,
            cafile="networkcert.pem",
            description="node {} (node)".format(self.node_id),
            prefix="nodes",
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
            description="node {} (member)".format(self.node_id),
            prefix="members",
            **kwargs,
        )
