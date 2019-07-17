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
import re

from loguru import logger as LOG

logging.getLogger("paramiko").setLevel(logging.WARNING)


class NodeNetworkState(Enum):
    stopped = 0
    started = 1
    joined = 2


@contextmanager
def network(
    hosts,
    build_directory,
    dbg_nodes=[],
    perf_nodes=[],
    create_nodes=True,
    node_offset=0,
    recovery=False,
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
            recovery=recovery,
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


class Network:
    node_args_to_forward = [
        "enclave_type",
        "log_level",
        "ignore_quote",
        "sig_max_tx",
        "sig_max_ms",
        "election_timeout",
        "memory_reserve_startup",
        "notify_server",
    ]

    # Maximum delay (seconds) for updates to propagate from the leader to followers
    replication_delay = 30

    def __init__(
        self,
        hosts,
        dbg_nodes=None,
        perf_nodes=None,
        create_nodes=True,
        node_offset=0,
        recovery=False,
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
                    recovery=recovery,
                )

    def start_and_join(self, args):
        cmd = ["rm", "-f"] + glob("member*.pem")
        infra.proc.ccall(*cmd)

        hosts = self.hosts or ["localhost"] * number_of_local_nodes()

        node_status = args.node_status or ["pending"] * len(hosts)
        if len(node_status) != len(hosts):
            raise ValueError("Node statuses are not equal to number of nodes.")

        if not args.package:
            raise ValueError("A package name must be specified.")

        LOG.info("Starting nodes on {}".format(hosts))

        for i, node in enumerate(self.nodes):
            dict_args = vars(args)
            forwarded_args = {
                arg: dict_args[arg] for arg in Network.node_args_to_forward
            }
            try:
                node.start(
                    lib_name=args.package,
                    node_status=node_status[i],
                    workspace=args.workspace,
                    label=args.label,
                    other_quote=None,
                    other_quoted_data=None,
                    **forwarded_args,
                )
            except Exception:
                LOG.exception("Failed to start node {}".format(i))
                raise
        LOG.info("All remotes started")

        if args.app_script:
            infra.proc.ccall("cp", args.app_script, args.build_dir).check_returncode()
        if args.gov_script:
            infra.proc.ccall("cp", args.gov_script, args.build_dir).check_returncode()
        LOG.info("Lua scripts copied")

        self.nodes_json()
        self.add_members([1, 2, 3])
        self.add_users([1, 2, 3])
        self.genesis_generator(args)

        primary = self.nodes[0]
        primary.start_network(self)

        for node in self.nodes[1:]:
            node.join_network(self)

        primary.network_state = NodeNetworkState.joined

        LOG.success("All nodes joined Network")

        return primary, self.nodes[1:]

    def start_in_recovery(self, args, ledger_file, sealed_secrets):
        hosts = self.hosts or ["localhost"] * number_of_local_nodes()

        node_status = args.node_status or ["pending"] * len(hosts)
        if len(node_status) != len(hosts):
            raise ValueError("Node statuses are not equal to number of nodes.")

        if not args.package:
            raise ValueError("A package name must be specified.")

        LOG.info("Starting nodes on {}".format(hosts))

        for i, node in enumerate(self.nodes):
            forwarded_args = {
                arg: getattr(args, arg)
                for arg in infra.ccf.Network.node_args_to_forward
            }
            try:
                node.start(
                    lib_name=args.package,
                    node_status=node_status[i],
                    ledger_file=ledger_file,
                    sealed_secrets=sealed_secrets,
                    workspace=args.workspace,
                    label=args.label,
                    **forwarded_args,
                )
            except Exception:
                LOG.exception("Failed to start recovery node {}".format(i))
                raise
        LOG.info("All remotes started")

        if args.app_script:
            infra.proc.ccall("cp", args.app_script, args.build_dir).check_returncode()
        if args.gov_script:
            infra.proc.ccall("cp", args.gov_script, args.build_dir).check_returncode()
        LOG.info("Lua scripts copied")

        primary = self.nodes[0]
        return primary, self.nodes[1:]

    def create_node(self, local_node_id, host, debug=False, perf=False, recovery=False):
        node = Node(local_node_id, host, debug, perf, recovery)
        self.nodes.append(node)
        return node

    def remove_last_node(self):
        last_node = self.nodes.pop()

    def add_node(self, new_node_info):
        with self.find_leader()[0].member_client(format="json") as member_client:
            j_result = member_client.rpc("add_node", new_node_info)

        return j_result

    def create_and_add_node(
        self, lib_name, args, should_succeed=True, local_node_id=None
    ):
        forwarded_args = {
            arg: getattr(args, arg) for arg in infra.ccf.Network.node_args_to_forward
        }
        if local_node_id is None:
            local_node_id = self.get_next_local_node_id()
        node_status = args.node_status or "pending"
        new_node = self.create_node(local_node_id, "localhost")
        new_node.start(
            lib_name=lib_name,
            node_status=node_status,
            workspace=args.workspace,
            label=args.label,
            **forwarded_args,
        )
        new_node_info = new_node.remote.info()

        j_result = self.add_node(new_node_info)

        if j_result.error is not None:
            self.remove_last_node()
            return (False, j_result.error["code"])

        new_node.node_id = j_result.result["id"]

        return (True, new_node)

    def add_members(self, members):
        self.members.extend(members)
        members = ["member{}".format(m) for m in members]
        for m in members:
            infra.proc.ccall(
                "./genesisgenerator", "cert", "--name={}".format(m)
            ).check_returncode()

    def add_users(self, users):
        users = ["user{}".format(u) for u in users]
        for u in users:
            infra.proc.ccall(
                "./genesisgenerator", "cert", "--name={}".format(u)
            ).check_returncode()

    def member_client_rpc_as_json(self, member_id, remote_node, *args):
        if remote_node is None:
            remote_node = self.find_leader()[0]

        result = infra.proc.ccall(
            "./memberclient",
            f"--cert=member{member_id}_cert.pem",
            f"--privk=member{member_id}_privk.pem",
            f"--host={remote_node.host}",
            f"--port={remote_node.tls_port}",
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

    def vote_using_majority(self, remote_node, proposal_id, accept):
        # There is no need to stop after n / 2 + 1 members have voted,
        # but this could prove to be useful in detecting errors
        # related to the voting mechanism
        member_count = int(len(self.members) / 2 + 1)
        for i, member in enumerate(self.members):
            if i >= member_count:
                break
            res = self.vote(member, remote_node, proposal_id, accept)
            assert res[0]
            if res[1]:
                break

        assert res

    def vote(self, member_id, remote_node, proposal_id, accept, force_unsigned=False):
        j_result = self.member_client_rpc_as_json(
            member_id,
            remote_node,
            "vote",
            f"--proposal-id={proposal_id}",
            "--accept" if accept else "--reject",
            "--sign" if not force_unsigned else "--force-unsigned",
        )
        if j_result.get("error") is not None:
            return (False, j_result["error"])
        return (True, j_result["result"])

    def propose_retire_node(self, member_id, remote_node, node_id):
        return self.propose(
            member_id, remote_node, "retire_node", f"--node-id={node_id}"
        )

    def retire_node(self, member_id, remote_node, node_id):
        result = self.propose_retire_node(member_id, remote_node, node_id)
        proposal_id = result[1]["id"]
        result = self.vote_using_majority(remote_node, proposal_id, True)

        with remote_node.member_client() as c:
            id = c.request("read", {"table": "nodes", "key": node_id})
            assert c.response(id).result["status"].decode() == "RETIRED"

    def propose_add_member(self, member_id, remote_node, new_member_cert):
        return self.propose(
            member_id, remote_node, "add_member", f"--member_cert={new_member_cert}"
        )

    def genesis_generator(self, args):
        gen = ["./genesisgenerator", "tx"]
        if args.app_script:
            gen.append("--app-script={}".format(args.app_script))
        if args.gov_script:
            gen.append("--gov-script={}".format(args.gov_script))
        infra.proc.ccall(*gen).check_returncode()
        LOG.info("Created Genesis TX")

    def nodes_json(self):
        nodes_json = [node.node_json for node in self.nodes]
        with open("nodes.json", "w") as nodes_:
            json.dump(nodes_json, nodes_, indent=4)
        LOG.info("Created nodes.json")

    def stop_all_nodes(self):
        for node in self.nodes:
            node.stop()
        LOG.info("All remotes stopped...")

    def all_nodes_debug(self):
        for node in self.nodes:
            node.debug = True

    def get_members(self):
        return self.members

    def get_running_nodes(self):
        return [node for node in self.nodes if node.is_stopped() is not True]

    def get_node_by_id(self, node_id):
        return next((node for node in self.nodes if node.node_id == node_id), None)

    def get_node_by_local_id(self, local_node_id):
        return next(
            (node for node in self.nodes if node.local_node_id == local_node_id), None
        )

    def find_leader(self):
        """
        Find the identity of the leader in the network and return its identity and the current term.
        """
        leader_id = None
        term = None

        for node in self.get_running_nodes():
            with node.management_client() as c:
                id = c.request("getLeaderInfo", {})
                res = c.response(id)
                if res.error is None:
                    leader_id = res.result["leader_id"]
                    term = res.term
                    break
                else:
                    assert (
                        res.error["code"] == infra.jsonrpc.ErrorCode.TX_LEADER_UNKNOWN
                    ), "RPC error code is not TX_NOT_LEADER"
        assert leader_id is not None, "No leader found"

        return (self.get_node_by_id(leader_id), term)

    def update_nodes(self):
        leader = self.find_leader()[0]
        with leader.management_client() as c:
            id = c.request("getNetworkInfo", {})
            res = c.response(id)

            # this is a json array of all the nodes in TRUSTED state
            active_nodes = res.result["nodes"]

            active_local_nodes = list(filter(lambda node: node.is_joined(), self.nodes))
            assert len(active_nodes) == len(
                active_local_nodes
            ), f"active node count ({len(active_nodes)}) does not match active local nodes ({len(active_local_nodes)})"

            for node in active_nodes:
                port = int(node["port"].decode())
                local_node = next(
                    (
                        local_node
                        for local_node in active_local_nodes
                        if local_node.tls_port == port
                    ),
                    None,
                )
                # make sure we know all the nodes
                assert (
                    local_node
                ), f"The node {str(node['host'])}:{port} is not known to the local network environment"

                node_id = int(node["node_id"])
                if local_node.node_id != node_id:
                    local_node.node_id = node_id
                    LOG.info(
                        "Correcting node id for {local_node.node_id} to be {node_id}"
                    )

    def wait_for_node_commit_sync(self):
        """
        Wait for commit level to get in sync on all nodes. This is expected to
        happen once CFTR has been established, in the absence of new transactions.
        """
        for _ in range(3):
            commits = []
            for node in (node for node in self.nodes if node.is_joined()):
                with node.management_client() as c:
                    id = c.request("getCommit", {})
                    commits.append(c.response(id).commit)
            if [commits[0]] * len(commits) == commits:
                break
            time.sleep(1)
        assert [commits[0]] * len(commits) == commits, "All nodes at the same commit"

    def get_primary(self):
        return self.nodes[0]

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
                for i in range(timeout * 10):
                    r = self.management_client.rpc(
                        "getCommit", {"commit": rpc_result.commit}
                    )
                    if (
                        r.global_commit >= rpc_result.commit
                        and r.result["term"] == rpc_result.term
                    ):
                        return
                    time.sleep(0.1)
                raise TimeoutError("Timed out waiting for commit")

            if self.notification_queue:
                for i in range(timeout * 10):
                    for q in list(self.notification_queue.queue):
                        if json.loads(q)["commit"] >= rpc_result.commit:
                            return
                    time.sleep(0.5)
                raise TimeoutError("Timed out waiting for notification")


@contextmanager
def node(
    local_node_id,
    host,
    build_directory,
    debug=False,
    perf=False,
    recovery=False,
    verify_quote=False,
    pdb=False,
):
    """
    Context manager for Node class.
    :param local_node_id: unique ID of node - relevant only for the python environment
    :param build_directory: the build directory
    :param host: node's hostname
    :param debug: default: False. If set, node will not start (user is prompted to start them manually)
    :param perf: default: False. If set, node will run under perf record
    :param recovery: default: False. If set, node will start in recovery
    :param verify_quote: default: False. If set, node will only verify a quote and shutdown immediately.
    :return: a Node instance that can be used to build a CCF network
    """
    with infra.path.working_dir(build_directory):
        node = Node(
            local_node_id=local_node_id,
            host=host,
            debug=debug,
            perf=perf,
            recovery=recovery,
            verify_quote=verify_quote,
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


class Node:
    def __init__(
        self,
        local_node_id,
        host,
        debug=False,
        perf=False,
        recovery=False,
        verify_quote=False,
    ):
        self.node_id = local_node_id
        self.local_node_id = local_node_id
        self.debug = debug
        self.perf = perf
        self.recovery = recovery
        self.verify_quote = verify_quote
        self.remote = None
        self.node_json = None
        self.network_state = NodeNetworkState.stopped

        hosts, *port = host.split(":")
        self.host, *self.pubhost = hosts.split(",")
        self.tls_port = port[0] if port else None

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
        if self.tls_port is None:
            self.raft_port, self.tls_port = infra.net.two_different(
                probably_free_function, self.host
            )
        else:
            self.raft_port = probably_free_function(self.host)

    def start(
        self,
        lib_name,
        enclave_type,
        workspace,
        label,
        other_quote=None,
        other_quoted_data=None,
        **kwargs,
    ):
        """
        Creates a CCFRemote instance, sets it up (connects, creates the directory and ships over the files), and
        (optionally) starts the node by executing the appropriate command.
        If self.debug is set to True, it will not actually start up the node, but will prompt the user to do so manually
        Raises exception if failed to prepare or start the node
        :param lib_name: the enclave package to load
        :param enclave_type: default: debug. Choices: 'simulate', 'debug', 'virtual'
        :param workspace: directory where node is started
        :param label: label for this node (to differentiate nodes from different test runs)
        :param other_quote: when starting a node in verify mode, path to other node's quote
        :param other_quoted_data: when starting a node in verify node, path to other node's quoted_data
        :return: void
        """
        lib_path = infra.path.build_lib_path(lib_name, enclave_type)
        self.remote = infra.remote.CCFRemote(
            lib_path,
            str(self.local_node_id),
            self.host,
            self.pubhost,
            self.raft_port,
            self.tls_port,
            self.remote_impl,
            enclave_type,
            self.verify_quote,
            workspace,
            label,
            other_quote,
            other_quoted_data,
            **kwargs,
        )
        self.remote.setup()
        LOG.info("Remote {} started".format(self.local_node_id))
        self.network_state = NodeNetworkState.started
        if self.recovery:
            self.remote.set_recovery()
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
            self.node_json = self.remote.info()
        else:
            if self.perf:
                self.remote.set_perf()
            self.remote.start()
            if not self.verify_quote:
                self.node_json = self.remote.info()

    def stop(self):
        if self.remote:
            self.remote.stop()
            self.network_state = NodeNetworkState.stopped

    def is_stopped(self):
        return self.network_state == NodeNetworkState.stopped

    def is_joined(self):
        return self.network_state == NodeNetworkState.joined

    def start_network(self, network):
        infra.proc.ccall(
            "./client",
            "--host={}".format(self.host),
            "--port={}".format(self.tls_port),
            "--ca={}".format(self.remote.pem),
            "startnetwork",
            "--req=@startNetwork.json",
        ).check_returncode()
        LOG.info("Started Network")
        with open("networkcert.pem", mode="rb") as cafile:
            network.net_cert = list(cafile.read())

    def complete_join_network(self):
        LOG.info("Joining Network")
        self.network_state = NodeNetworkState.joined

    def join_network(self, network):
        leader, term = network.find_leader()
        with self.management_client(format="json") as c:
            res = c.rpc(
                "joinNetwork",
                {
                    "hostname": leader.host,
                    "service": str(leader.tls_port),
                    "network_cert": network.net_cert,
                },
            )
            assert res.error is None
        self.complete_join_network()

    def set_recovery(self):
        self.remote.set_recovery()

    def restart(self):
        self.remote.restart()

    def get_sealed_secrets(self):
        return self.remote.get_sealed_secrets()

    def user_client(self, format="msgpack", user_id=1, **kwargs):
        return infra.jsonrpc.client(
            self.host,
            self.tls_port,
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
            self.tls_port,
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
            self.tls_port,
            "members",
            cert="member{}_cert.pem".format(member_id),
            key="member{}_privk.pem".format(member_id),
            cafile="networkcert.pem",
            description="node {} (member)".format(self.local_node_id),
            **kwargs,
        )
