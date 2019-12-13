# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import json
import os
import time
import logging
from contextlib import contextmanager
from glob import glob
from enum import Enum, IntEnum
import infra.clients
import infra.path
import infra.proc
import infra.node
import infra.consortium
import infra.jsonrpc
import ssl
import random

from loguru import logger as LOG

logging.getLogger("paramiko").setLevel(logging.WARNING)


class ServiceStatus(Enum):
    OPENING = 1
    OPEN = 2
    CLOSED = 3


class ParticipantsCurve(IntEnum):
    secp384r1 = 0
    secp256k1 = 1
    ed25519 = 2

    def __str__(self):
        return self.name

    def next(self):
        return ParticipantsCurve((self.value + 1) % len(ParticipantsCurve))


class Network:
    node_args_to_forward = [
        "enclave_type",
        "host_log_level",
        "ignore_quote",
        "sig_max_tx",
        "sig_max_ms",
        "election_timeout",
        "consensus",
        "memory_reserve_startup",
        "notify_server",
        "json_log_path",
        "gov_script",
    ]

    # Maximum delay (seconds) for updates to propagate from the primary to backups
    replication_delay = 30

    def __init__(self, hosts, dbg_nodes=None, perf_nodes=None, existing_network=None):
        if existing_network is None:
            self.consortium = []
            self.node_offset = 0
        else:
            self.consortium = existing_network.consortium
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

    def _get_next_local_node_id(self):
        if len(self.nodes):
            return self.nodes[-1].node_id + 1
        return self.node_offset

    def create_node(self, host):
        node_id = self._get_next_local_node_id()
        debug = (
            (str(node_id) in self.dbg_nodes) if self.dbg_nodes is not None else False
        )
        perf = (
            (str(node_id) in self.perf_nodes) if self.perf_nodes is not None else False
        )
        node = infra.node.Node(node_id, host, debug, perf)
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
        if self.status == ServiceStatus.OPENING:
            if args.consensus != "pbft":
                try:
                    node.wait_for_node_to_join()
                except TimeoutError:
                    LOG.error(f"New node {node.node_id} failed to join the network")
                    raise
            node.network_state = infra.node.NodeNetworkState.joined

    def _start_all_nodes(
        self, args, recovery=False, ledger_file=None, sealed_secrets=None
    ):
        hosts = self.hosts or ["localhost"] * number_of_local.nodes()

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
                            members_certs=self.consortium.get_members_certs(),
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
        self.consortium.check_for_service(primary, status=ServiceStatus.OPENING)

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

        self.consortium = infra.consortium.Consortium([0, 1, 2], args.default_curve)
        self.initial_users = [0, 1, 2]
        self.create_users(self.initial_users, args.default_curve)

        if args.gov_script:
            infra.proc.ccall("cp", args.gov_script, args.build_dir).check_returncode()
        LOG.info("Lua scripts copied")

        primary = self._start_all_nodes(args)

        if args.consensus != "pbft":
            self.wait_for_all_nodes_to_catch_up(primary)
        LOG.success("All nodes joined network")

        if args.app_script:
            infra.proc.ccall("cp", args.app_script, args.build_dir).check_returncode()
            self.consortium.set_lua_app(
                member_id=1, remote_node=primary, app_script=args.app_script
            )

        self.consortium.add_users(primary, self.initial_users)
        LOG.info("Initial set of users added")

        self.consortium.open_network(
            member_id=1, remote_node=primary, pbft_open=args.consensus != "pbft"
        )
        self.status = ServiceStatus.OPEN
        LOG.success("***** Network is now open *****")

    def start_in_recovery(self, args, ledger_file, sealed_secrets):
        primary = self._start_all_nodes(
            args, recovery=True, ledger_file=ledger_file, sealed_secrets=sealed_secrets
        )
        self.wait_for_all_nodes_to_catch_up(primary)
        LOG.success("All nodes joined recovered public network")

    def stop_all_nodes(self):
        for node in self.nodes:
            node.stop()
        LOG.info("All remotes stopped...")

    def create_and_add_pending_node(self, lib_name, host, args, target_node=None):
        """
        Create a new node and add it to the network. Note that the new node
        still needs to be trusted by members to complete the join protocol.
        """
        new_node = self.create_node(host)
        self._add_node(new_node, lib_name, args, target_node)
        primary, _ = self.find_primary()
        try:
            self.consortium.wait_for_node_to_exist_in_store(
                primary,
                new_node.node_id,
                (
                    infra.node.NodeStatus.PENDING
                    if self.status == ServiceStatus.OPEN
                    else infra.node.NodeStatus.TRUSTED
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

        primary, _ = self.find_primary()
        try:
            if self.status is ServiceStatus.OPEN:
                self.consortium.trust_node(1, primary, new_node.node_id)
            if args.consensus != "pbft":
                new_node.wait_for_node_to_join()
        except (ValueError, TimeoutError):
            LOG.error(f"New trusted node {new_node.node_id} failed to join the network")
            new_node.stop()
            return None

        new_node.network_state = infra.node.NodeNetworkState.joined
        if args.consensus != "pbft":
            self.wait_for_all_nodes_to_catch_up(primary)

        return new_node

    def create_users(self, users, curve):
        users = ["user{}".format(u) for u in users]
        for u in users:
            infra.proc.ccall(
                "./keygenerator.sh", f"{u}", curve.name, log_output=False
            ).check_returncode()

    def get_members(self):
        return self.consortium.members

    def get_joined_nodes(self):
        return [node for node in self.nodes if node.is_joined()]

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
        if state == "partOfNetwork":
            self.status = ServiceStatus.OPEN

    def wait_for_all_nodes_to_be_trusted(self, timeout=3):
        primary, term = self.find_primary()
        for n in self.nodes:
            self.consortium.wait_for_node_to_exist_in_store(
                primary, n.node_id, infra.node.NodeStatus.TRUSTED
            )

    def _get_node_by_id(self, node_id):
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
        return (self._get_node_by_id(primary_id), term)

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
