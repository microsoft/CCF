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
import ssl
import random
import http
from math import ceil

from loguru import logger as LOG

logging.getLogger("paramiko").setLevel(logging.WARNING)

# JOIN_TIMEOUT should be greater than the worst case quote verification time (~ 25 secs)
JOIN_TIMEOUT = 40

COMMON_FOLDER = "common"


class ServiceStatus(Enum):
    OPENING = 1
    OPEN = 2
    CLOSED = 3


class ParticipantsCurve(IntEnum):
    secp384r1 = 0
    secp256k1 = 1
    # ed25519 = 2 TODO: Unsupported for now

    def __str__(self):
        return self.name

    def next(self):
        return ParticipantsCurve((self.value + 1) % len(ParticipantsCurve))


class PrimaryNotFound(Exception):
    pass


class CodeIdNotFound(Exception):
    pass


class NodeShutdownError(Exception):
    pass


def get_common_folder_name(workspace, label):
    return os.path.join(workspace, f"{label}_{COMMON_FOLDER}")


class Network:
    KEY_GEN = "keygenerator.sh"
    node_args_to_forward = [
        "enclave_type",
        "host_log_level",
        "sig_max_tx",
        "sig_max_ms",
        "raft_election_timeout",
        "pbft_view_change_timeout",
        "consensus",
        "memory_reserve_startup",
        "notify_server",
        "json_log_path",
        "gov_script",
        "join_timer",
        "worker_threads",
    ]

    # Maximum delay (seconds) for updates to propagate from the primary to backups
    replication_delay = 30

    def __init__(
        self,
        hosts,
        binary_dir=".",
        dbg_nodes=None,
        perf_nodes=None,
        existing_network=None,
        txs=None,
    ):
        if existing_network is None:
            self.consortium = []
            self.node_offset = 0
            self.txs = txs
        else:
            self.consortium = existing_network.consortium
            # When creating a new network from an existing one (e.g. for recovery),
            # the node id of the nodes of the new network should start from the node
            # id of the existing network, so that new nodes id match the ones in the
            # nodes KV table
            self.node_offset = (
                len(existing_network.nodes) + existing_network.node_offset
            )
            self.txs = existing_network.txs

        self.ignoring_shutdown_errors = False
        self.nodes = []
        self.hosts = hosts
        self.status = ServiceStatus.CLOSED
        self.binary_dir = binary_dir
        self.key_generator = os.path.join(binary_dir, self.KEY_GEN)
        if not os.path.isfile(self.key_generator):
            raise FileNotFoundError(
                f"Could not find key generator script at '{self.key_generator}' - is binary directory set correctly?"
            )
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
        node = infra.node.Node(node_id, host, self.binary_dir, debug, perf)
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
            common_dir=self.common_dir,
            target_rpc_address=f"{target_node.host}:{target_node.rpc_port}",
            **forwarded_args,
        )

        # If the network is opening, node are trusted without consortium approval
        if self.status == ServiceStatus.OPENING:
            if args.consensus != "pbft":
                try:
                    node.wait_for_node_to_join(timeout=JOIN_TIMEOUT)
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
            try:
                if i == 0:
                    if not recovery:
                        node.start(
                            lib_name=args.package,
                            workspace=args.workspace,
                            label=args.label,
                            common_dir=self.common_dir,
                            members_info=self.consortium.get_members_info(),
                            **forwarded_args,
                        )
                    else:
                        node.recover(
                            lib_name=args.package,
                            ledger_file=ledger_file,
                            sealed_secrets=sealed_secrets,
                            workspace=args.workspace,
                            label=args.label,
                            common_dir=self.common_dir,
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

    def _setup_common_folder(self, gov_script):
        LOG.info(f"Creating common folder: {self.common_dir}")
        cmd = ["rm", "-rf", self.common_dir]
        assert (
            infra.proc.ccall(*cmd).returncode == 0
        ), f"Could not remove {self.common_dir} directory"
        cmd = ["mkdir", "-p", self.common_dir]
        assert (
            infra.proc.ccall(*cmd).returncode == 0
        ), f"Could not create {self.common_dir} directory"
        cmd = ["cp", gov_script, self.common_dir]
        assert (
            infra.proc.ccall(*cmd).returncode == 0
        ), f"Could not copy governance {gov_script} to {self.common_dir}"
        # It is more convenient to create a symlink in the common directory than generate
        # certs and keys in the top directory and move them across
        cmd = ["ln", "-s", os.path.join(os.getcwd(), self.KEY_GEN), self.common_dir]
        assert (
            infra.proc.ccall(*cmd).returncode == 0
        ), f"Could not symlink {self.KEY_GEN} to {self.common_dir}"

    def start_and_join(self, args):
        """
        Starts a CCF network.
        :param args: command line arguments to configure the CCF nodes.
        """
        self.common_dir = get_common_folder_name(args.workspace, args.label)
        self._setup_common_folder(args.gov_script)

        initial_member_ids = list(range(max(1, args.initial_member_count)))
        self.consortium = infra.consortium.Consortium(
            initial_member_ids,
            args.participants_curve,
            self.key_generator,
            self.common_dir,
        )
        self.initial_users = list(range(max(0, args.initial_user_count)))
        self.create_users(self.initial_users, args.participants_curve)

        primary = self._start_all_nodes(args)

        if args.consensus != "pbft":
            self.wait_for_all_nodes_to_catch_up(primary)
        LOG.success("All nodes joined network")

        if args.app_script:
            infra.proc.ccall("cp", args.app_script, args.binary_dir).check_returncode()
            self.consortium.set_lua_app(remote_node=primary, app_script=args.app_script)

        if args.js_app_script:
            infra.proc.ccall(
                "cp", args.js_app_script, args.binary_dir
            ).check_returncode()
            self.consortium.set_js_app(
                remote_node=primary, app_script=args.js_app_script
            )

        self.consortium.add_users(primary, self.initial_users)
        LOG.info("Initial set of users added")

        self.consortium.open_network(
            remote_node=primary, pbft_open=(args.consensus == "pbft")
        )
        self.status = ServiceStatus.OPEN
        LOG.success("***** Network is now open *****")

    def start_in_recovery(self, args, ledger_file, sealed_secrets):
        self.common_dir = get_common_folder_name(args.workspace, args.label)
        primary = self._start_all_nodes(
            args, recovery=True, ledger_file=ledger_file, sealed_secrets=sealed_secrets
        )
        self.wait_for_all_nodes_to_catch_up(primary)
        LOG.success("All nodes joined recovered public network")

    def ignore_errors_on_shutdown(self):
        self.ignoring_shutdown_errors = True

    def stop_all_nodes(self):
        fatal_error_found = False
        for node in self.nodes:
            _, fatal_errors = node.stop()
            if fatal_errors:
                fatal_error_found = True

        LOG.info("All remotes stopped...")

        if fatal_error_found:
            if self.ignoring_shutdown_errors:
                LOG.warning("Ignoring shutdown errors")
            else:
                raise NodeShutdownError(f"Fatal error found during node shutdown")

    def create_and_add_pending_node(
        self, lib_name, host, args, target_node=None, timeout=JOIN_TIMEOUT
    ):
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
                timeout=timeout,
                node_status=(
                    infra.node.NodeStatus.PENDING
                    if self.status == ServiceStatus.OPEN
                    else infra.node.NodeStatus.TRUSTED
                ),
            )
        except TimeoutError as err:
            # The node can be safely discarded since it has not been
            # attributed a unique node_id by CCF
            LOG.error(f"New pending node {new_node.node_id} failed to join the network")
            errors, _ = new_node.stop()
            self.nodes.remove(new_node)
            if errors:
                # Throw accurate exceptions if known errors found in
                for error in errors:
                    if "CODE_ID_NOT_FOUND" in error:
                        raise CodeIdNotFound
            raise

        return new_node

    def create_and_trust_node(self, lib_name, host, args, target_node=None):
        """
        Create a new node, add it to the network and let members vote to trust
        it so that it becomes part of the consensus protocol.
        """
        new_node = self.create_and_add_pending_node(lib_name, host, args, target_node)

        primary, _ = self.find_primary()
        try:
            if self.status is ServiceStatus.OPEN:
                self.consortium.trust_node(primary, new_node.node_id)
            if args.consensus != "pbft":
                # Here, quote verification has already been run when the node
                # was added as pending. Only wait for the join timer for the
                # joining node to retrieve network secrets.
                new_node.wait_for_node_to_join(timeout=ceil(args.join_timer * 2 / 1000))
        except (ValueError, TimeoutError):
            LOG.error(f"New trusted node {new_node.node_id} failed to join the network")
            new_node.stop()
            raise

        new_node.network_state = infra.node.NodeNetworkState.joined
        if args.consensus != "pbft":
            self.wait_for_all_nodes_to_catch_up(primary)

        return new_node

    def create_user(self, user_id, curve):
        infra.proc.ccall(
            self.key_generator,
            f"--name=user{user_id}",
            f"--curve={curve.name}",
            path=self.common_dir,
            log_output=False,
        ).check_returncode()

    def create_users(self, user_ids, curve):
        for user_id in user_ids:
            self.create_user(user_id, curve)

    def get_members(self):
        return self.consortium.members

    def get_joined_nodes(self):
        return [node for node in self.nodes if node.is_joined()]

    def wait_for_state(self, node, state, timeout=3):
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                with node.node_client() as c:
                    r = c.get("getSignedIndex")
                    if r.result["state"] == state:
                        break
            except ConnectionRefusedError:
                pass
            time.sleep(0.1)
        else:
            raise TimeoutError(
                f"Timed out waiting for state {state} on node {node.node_id}"
            )
        if state == "partOfNetwork":
            self.status = ServiceStatus.OPEN

    def wait_for_all_nodes_to_be_trusted(self, timeout=3):
        primary, term = self.find_primary()
        for n in self.nodes:
            self.consortium.wait_for_node_to_exist_in_store(
                primary, n.node_id, timeout, infra.node.NodeStatus.TRUSTED
            )

    def _get_node_by_id(self, node_id):
        return next((node for node in self.nodes if node.node_id == node_id), None)

    def find_primary(self, timeout=3, request_timeout=3):
        """
        Find the identity of the primary in the network and return its identity
        and the current term.
        """
        primary_id = None
        term = None

        end_time = time.time() + timeout
        while time.time() < end_time:
            for node in self.get_joined_nodes():
                with node.node_client(request_timeout=request_timeout) as c:
                    try:
                        res = c.get("getPrimaryInfo")
                        if res.error is None:
                            primary_id = res.result["primary_id"]
                            term = res.term
                            break
                        else:
                            assert "Primary unknown" in res.error, res.error
                    except TimeoutError:
                        pass
            if primary_id is not None:
                break
            time.sleep(0.1)

        if primary_id is None:
            raise PrimaryNotFound
        return (self._get_node_by_id(primary_id), term)

    def find_backups(self, primary=None, timeout=3):
        if primary is None:
            primary, term = self.find_primary(timeout=timeout)
        return [n for n in self.get_joined_nodes() if n != primary]

    def find_any_backup(self, primary=None, timeout=3):
        return random.choice(self.find_backups(primary=primary, timeout=timeout))

    def find_nodes(self, timeout=3):
        primary, term = self.find_primary(timeout=timeout)
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
            res = c.get("getCommit")
            local_commit_leader = res.commit
            term_leader = res.term

        end_time = time.time() + timeout
        while time.time() < end_time:
            caught_up_nodes = []
            for node in self.get_joined_nodes():
                with node.node_client() as c:
                    resp = c.get("getCommit")
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
            time.sleep(0.1)
        assert len(caught_up_nodes) == len(
            self.get_joined_nodes()
        ), f"Only {len(caught_up_nodes)} (out of {len(self.get_joined_nodes())}) nodes have joined the network"

    def wait_for_node_commit_sync(self, consensus, timeout=3):
        """
        Wait for commit level to get in sync on all nodes. This is expected to
        happen once CFTR has been established, in the absence of new transactions.
        """
        end_time = time.time() + timeout
        while time.time() < end_time:
            commits = []
            for node in self.get_joined_nodes():
                with node.node_client() as c:
                    r = c.get("getCommit")
                    commits.append(r.commit)
            if [commits[0]] * len(commits) == commits:
                break
            time.sleep(0.1)
        # in pbft getCommit increments the commit version, so commits will not be the same
        # but they should be in ascending order
        assert (
            [commits[0]] * len(commits) == commits
            if consensus == "raft"
            else sorted(commits) == commits
        ), "All nodes in sync"

    def wait_for_sealed_secrets_at_version(self, version, timeout=5):
        """
        Wait for a sealed secret at a version larger than "version" to be sealed
        on all nodes.
        """
        end_time = time.time() + timeout
        while time.time() < end_time:
            rekeyed_nodes = []
            for node in self.get_joined_nodes():
                try:
                    max_sealed_version = int(
                        max(node.get_sealed_secrets(), key=lambda x: int(x))
                    )
                    if max_sealed_version >= version:
                        rekeyed_nodes.append(node)
                except IndexError:
                    pass
            if len(rekeyed_nodes) == len(self.get_joined_nodes()):
                break
            time.sleep(0.1)
        assert len(rekeyed_nodes) == len(
            self.get_joined_nodes()
        ), f"Only {len(rekeyed_nodes)} (out of {len(self.get_joined_nodes())}) nodes have been rekeyed"


@contextmanager
def network(
    hosts, binary_directory=".", dbg_nodes=[], perf_nodes=[], pdb=False, txs=None
):
    """
    Context manager for Network class.
    :param hosts: a list of hostnames (localhost or remote hostnames)
    :param binary_directory: the directory where CCF's binaries are located
    :param dbg_nodes: default: []. List of node id's that will not start (user is prompted to start them manually)
    :param perf_nodes: default: []. List of node ids that will run under perf record
    :param pdb: default: False. Debugger.
    :param txs: default: None. Transactions committed on that network.
    :return: a Network instance that can be used to create/access nodes, handle the genesis state (add members, create
    node.json), and stop all the nodes that belong to the network
    """
    net = Network(
        hosts=hosts,
        binary_dir=binary_directory,
        dbg_nodes=dbg_nodes,
        perf_nodes=perf_nodes,
        txs=txs,
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
