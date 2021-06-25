# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import time
import logging
from contextlib import contextmanager
from enum import Enum, IntEnum, auto
from ccf.clients import CCFConnectionException, flush_info
import infra.path
import infra.proc
import infra.node
import infra.consortium
from ccf.ledger import NodeStatus, Ledger
from ccf.tx_status import TxStatus
from ccf.tx_id import TxID
import random
from dataclasses import dataclass
from math import ceil
import http
import pprint

from loguru import logger as LOG

logging.getLogger("paramiko").setLevel(logging.WARNING)

# JOIN_TIMEOUT should be greater than the worst case quote verification time (~ 25 secs)
JOIN_TIMEOUT = 40

COMMON_FOLDER = "common"


class NodeRole(Enum):
    ANY = auto()
    PRIMARY = auto()
    BACKUP = auto()


class ServiceStatus(Enum):
    OPENING = "Opening"
    OPEN = "Open"
    CLOSED = "Closed"


class EllipticCurve(IntEnum):
    secp384r1 = 0
    secp256r1 = 1

    def next(self):
        return EllipticCurve((self.value + 1) % len(EllipticCurve))


class PrimaryNotFound(Exception):
    pass


class CodeIdNotFound(Exception):
    pass


class StartupSnapshotIsOld(Exception):
    pass


class NodeShutdownError(Exception):
    pass


def get_common_folder_name(workspace, label):
    return os.path.join(workspace, f"{label}_{COMMON_FOLDER}")


@dataclass
class UserInfo:
    local_id: int
    service_id: str


class Network:
    KEY_GEN = "keygenerator.sh"
    SHARE_SCRIPT = "submit_recovery_share.sh"
    node_args_to_forward = [
        "enclave_type",
        "host_log_level",
        "sig_tx_interval",
        "sig_ms_interval",
        "raft_election_timeout_ms",
        "bft_view_change_timeout_ms",
        "consensus",
        "memory_reserve_startup",
        "log_format_json",
        "constitution",
        "join_timer",
        "worker_threads",
        "ledger_chunk_bytes",
        "domain",
        "san",
        "snapshot_tx_interval",
        "max_open_sessions",
        "max_open_sessions_hard",
        "jwt_key_refresh_interval_s",
        "common_read_only_ledger_dir",
        "curve_id",
        "client_connection_timeout_ms",
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
        jwt_issuer=None,
        library_dir=".",
        init_partitioner=False,
        version=None,
    ):
        if existing_network is None:
            self.consortium = None
            self.users = []
            self.node_offset = 0
            self.txs = txs
            self.jwt_issuer = jwt_issuer
        else:
            self.consortium = existing_network.consortium
            self.users = existing_network.users
            # When creating a new network from an existing one (e.g. for recovery),
            # the node id of the nodes of the new network should start from the node
            # id of the existing network, so that new nodes id match the ones in the
            # nodes KV table
            self.node_offset = (
                len(existing_network.nodes) + existing_network.node_offset
            )
            self.txs = existing_network.txs
            self.jwt_issuer = existing_network.jwt_issuer

        self.ignoring_shutdown_errors = False
        self.nodes = []
        self.hosts = hosts
        self.status = ServiceStatus.CLOSED
        self.binary_dir = binary_dir
        self.library_dir = library_dir
        self.common_dir = None
        self.election_duration = None
        self.key_generator = os.path.join(binary_dir, self.KEY_GEN)
        self.share_script = os.path.join(binary_dir, self.SHARE_SCRIPT)
        if not os.path.isfile(self.key_generator):
            raise FileNotFoundError(
                f"Could not find key generator script at '{self.key_generator}' - is binary directory set correctly?"
            )
        self.dbg_nodes = dbg_nodes
        self.perf_nodes = perf_nodes
        self.version = version

        # Requires admin privileges
        self.partitioner = (
            infra.partitions.Partitioner(self) if init_partitioner else None
        )

        try:
            os.remove("/tmp/vscode-gdb.sh")
        except FileNotFoundError:
            pass

        for host in hosts:
            self.create_node(host, version=self.version)

    def _get_next_local_node_id(self):
        if len(self.nodes):
            return self.nodes[-1].local_node_id + 1
        return self.node_offset

    def create_node(
        self, host, binary_dir=None, library_dir=None, node_port=None, version=None
    ):
        node_id = self._get_next_local_node_id()
        debug = (
            (str(node_id) in self.dbg_nodes) if self.dbg_nodes is not None else False
        )
        perf = (
            (str(node_id) in self.perf_nodes) if self.perf_nodes is not None else False
        )
        node = infra.node.Node(
            node_id,
            host,
            binary_dir or self.binary_dir,
            library_dir or self.library_dir,
            debug,
            perf,
            node_port=node_port,
            version=version,
        )
        self.nodes.append(node)
        return node

    def _add_node(
        self,
        node,
        lib_name,
        args,
        target_node=None,
        recovery=False,
        ledger_dir=None,
        copy_ledger_read_only=True,
        read_only_ledger_dir=None,
        from_snapshot=True,
        snapshot_dir=None,
    ):
        forwarded_args = {
            arg: getattr(args, arg)
            for arg in infra.network.Network.node_args_to_forward
        }

        # Contact primary if no target node is set
        if target_node is None:
            target_node, _ = self.find_primary(
                timeout=args.ledger_recovery_timeout if recovery else 3
            )
        LOG.info(f"Joining from target node {target_node.local_node_id}")

        # Only retrieve snapshot from target node if the snapshot directory is not
        # specified
        if from_snapshot and snapshot_dir is None:
            snapshot_dir = self.get_committed_snapshots(target_node)

        committed_ledger_dir = None
        current_ledger_dir = None
        if from_snapshot:
            if os.listdir(snapshot_dir):
                LOG.info(f"Joining from snapshot directory: {snapshot_dir}")
                # Only when joining from snapshot, retrieve ledger dirs from target node
                # if the ledger directories are not specified. When joining without snapshot,
                # the entire ledger will be retransmitted by primary node
                current_ledger_dir = ledger_dir or None
                committed_ledger_dir = read_only_ledger_dir or None
                if copy_ledger_read_only and read_only_ledger_dir is None:
                    current_ledger_dir, committed_ledger_dir = target_node.get_ledger(
                        include_read_only_dirs=True
                    )
            else:
                LOG.warning(
                    f"Attempting to join from snapshot but {snapshot_dir} is empty: defaulting to complete replay of transaction history"
                )
        else:
            LOG.info(
                "Joining without snapshot: complete transaction history will be replayed"
            )

        node.join(
            lib_name=lib_name,
            workspace=args.workspace,
            label=args.label,
            common_dir=self.common_dir,
            target_rpc_address=f"{target_node.host}:{target_node.rpc_port}",
            snapshot_dir=snapshot_dir,
            ledger_dir=current_ledger_dir,
            read_only_ledger_dir=committed_ledger_dir,
            **forwarded_args,
        )

        # If the network is opening, node are trusted without consortium approval
        if self.status == ServiceStatus.OPENING:
            try:
                node.wait_for_node_to_join(timeout=JOIN_TIMEOUT)
            except TimeoutError:
                LOG.error(f"New node {node.node_id} failed to join the network")
                raise

    def _start_all_nodes(
        self,
        args,
        recovery=False,
        ledger_dir=None,
        read_only_ledger_dir=None,
        snapshot_dir=None,
    ):
        hosts = self.hosts

        if not args.package:
            raise ValueError("A package name must be specified.")

        self.status = ServiceStatus.OPENING
        LOG.info("Opening CCF service on {}".format(hosts))

        forwarded_args = {
            arg: getattr(args, arg)
            for arg in infra.network.Network.node_args_to_forward
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
                            workspace=args.workspace,
                            label=args.label,
                            common_dir=self.common_dir,
                            ledger_dir=ledger_dir,
                            read_only_ledger_dir=read_only_ledger_dir,
                            snapshot_dir=snapshot_dir,
                            **forwarded_args,
                        )
                        self.wait_for_state(
                            node,
                            infra.node.State.PART_OF_PUBLIC_NETWORK.value,
                            timeout=args.ledger_recovery_timeout,
                        )
                else:
                    # When a new service is started, initial nodes join without a snapshot
                    self._add_node(
                        node,
                        args.package,
                        args,
                        recovery=recovery,
                        ledger_dir=ledger_dir,
                        from_snapshot=snapshot_dir is not None,
                        read_only_ledger_dir=read_only_ledger_dir,
                        snapshot_dir=snapshot_dir,
                    )
            except Exception:
                LOG.exception("Failed to start node {}".format(node.node_id))
                raise

        self.election_duration = (
            args.bft_view_change_timeout_ms / 1000
            if args.consensus == "bft"
            else args.raft_election_timeout_ms / 1000
        ) * 2

        LOG.info("All nodes started")

        # Here, recovery nodes might still be catching up, and possibly swamp
        # the current primary which would not be able to serve user requests
        primary, _ = self.find_primary(
            timeout=args.ledger_recovery_timeout if recovery else 3
        )
        return primary

    def _setup_common_folder(self, constitution):
        LOG.info(f"Creating common folder: {self.common_dir}")
        cmd = ["rm", "-rf", self.common_dir]
        assert (
            infra.proc.ccall(*cmd).returncode == 0
        ), f"Could not remove {self.common_dir} directory"
        cmd = ["mkdir", "-p", self.common_dir]
        assert (
            infra.proc.ccall(*cmd).returncode == 0
        ), f"Could not create {self.common_dir} directory"
        for fragment in constitution:
            cmd = ["cp", fragment, self.common_dir]
            assert (
                infra.proc.ccall(*cmd).returncode == 0
            ), f"Could not copy governance {fragment} to {self.common_dir}"
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

        assert (
            args.constitution
        ), "--constitution argument must be provided to start a network"

        self._setup_common_folder(args.constitution)

        mc = max(1, args.initial_member_count)
        initial_members_info = []
        for i in range(mc):
            initial_members_info += [
                (
                    i,
                    (i < args.initial_recovery_member_count),
                    {"is_operator": True}
                    if (i < args.initial_operator_count)
                    else None,
                )
            ]

        self.consortium = infra.consortium.Consortium(
            self.common_dir,
            self.key_generator,
            self.share_script,
            args.consensus,
            initial_members_info,
            args.participants_curve,
            authenticate_session=not args.disable_member_session_auth,
        )
        initial_users = [
            f"user{user_id}" for user_id in list(range(max(0, args.initial_user_count)))
        ]
        self.create_users(initial_users, args.participants_curve)

        primary = self._start_all_nodes(args)
        self.wait_for_all_nodes_to_commit(primary=primary)
        LOG.success("All nodes joined network")

        self.consortium.activate(self.find_random_node())

        if args.js_app_bundle:
            self.consortium.set_js_app(
                remote_node=self.find_random_node(), app_bundle_path=args.js_app_bundle
            )

        for path in args.jwt_issuer:
            self.consortium.set_jwt_issuer(
                remote_node=self.find_random_node(), json_path=path
            )

        if self.jwt_issuer:
            self.jwt_issuer.register(self)

        self.consortium.add_users(self.find_random_node(), initial_users)
        LOG.info(f"Initial set of users added: {len(initial_users)}")

        self.consortium.transition_service_to_open(remote_node=self.find_random_node())
        self.status = ServiceStatus.OPEN
        LOG.success("***** Network is now open *****")

    def start_in_recovery(
        self,
        args,
        ledger_dir,
        committed_ledger_dir=None,
        snapshot_dir=None,
        common_dir=None,
    ):
        """
        Starts a CCF network in recovery mode.
        :param args: command line arguments to configure the CCF nodes.
        :param ledger_dir: ledger directory to recover from.
        :param snapshot_dir: snapshot directory to recover from.
        :param common_dir: common directory containing member and user keys and certs.
        """
        self.common_dir = common_dir or get_common_folder_name(
            args.workspace, args.label
        )
        ledger_dirs = [ledger_dir]
        if committed_ledger_dir:
            ledger_dirs.append(committed_ledger_dir)

        ledger = Ledger(ledger_dirs, committed_only=False)
        public_state, _ = ledger.get_latest_public_state()

        primary = self._start_all_nodes(
            args,
            recovery=True,
            ledger_dir=ledger_dir,
            read_only_ledger_dir=committed_ledger_dir,
            snapshot_dir=snapshot_dir,
        )

        # If a common directory was passed in, initialise the consortium from it
        if common_dir is not None:
            self.consortium = infra.consortium.Consortium(
                common_dir,
                self.key_generator,
                self.share_script,
                args.consensus,
                public_state=public_state,
            )

        for node in self.get_joined_nodes():
            self.wait_for_state(
                node,
                infra.node.State.PART_OF_PUBLIC_NETWORK.value,
                timeout=args.ledger_recovery_timeout,
            )
        # Catch-up in recovery can take a long time, so extend this timeout
        self.wait_for_all_nodes_to_commit(primary=primary, timeout=20)
        LOG.success("All nodes joined public network")

    def recover(self, args):
        """
        Recovers a CCF network previously started in recovery mode.
        :param args: command line arguments to configure the CCF nodes.
        """
        self.consortium.check_for_service(
            self.find_random_node(), status=ServiceStatus.OPENING
        )
        self.consortium.wait_for_all_nodes_to_be_trusted(
            self.find_random_node(), self.nodes
        )
        self.consortium.transition_service_to_open(self.find_random_node())
        self.consortium.recover_with_shares(self.find_random_node())

        for node in self.get_joined_nodes():
            self.wait_for_state(
                node,
                infra.node.State.PART_OF_NETWORK.value,
                timeout=args.ledger_recovery_timeout,
            )
            self._wait_for_app_open(node)

        self.consortium.check_for_service(self.find_random_node(), ServiceStatus.OPEN)
        LOG.success("***** Recovered network is now open *****")

    def ignore_errors_on_shutdown(self):
        self.ignoring_shutdown_errors = True

    def stop_all_nodes(self, skip_verification=False, verbose_verification=False):
        if not skip_verification:
            # Verify that all txs committed on the service can be read
            if self.txs is not None:
                log_capture = None if verbose_verification else []
                self.txs.verify(self, log_capture=log_capture)
                if verbose_verification:
                    flush_info(log_capture, None)

        fatal_error_found = False

        for node in self.nodes:
            _, fatal_errors = node.stop()
            if fatal_errors:
                fatal_error_found = True

        LOG.info("All nodes stopped")

        if not skip_verification:
            longest_ledger_seqno = 0
            most_up_to_date_node = None
            committed_ledger_dirs = {}

            for node in self.nodes:
                # Find stopped node with longest ledger
                _, committed_ledger_dir = node.get_ledger(include_read_only_dirs=True)
                ledger_end_seqno = 0
                for ledger_file in os.listdir(committed_ledger_dir):
                    end_seqno = infra.node.get_committed_ledger_end_seqno(ledger_file)
                    if end_seqno > ledger_end_seqno:
                        ledger_end_seqno = end_seqno

                if ledger_end_seqno > longest_ledger_seqno:
                    longest_ledger_seqno = ledger_end_seqno
                    most_up_to_date_node = node
                committed_ledger_dirs[node.local_node_id] = [
                    committed_ledger_dir,
                    ledger_end_seqno,
                ]

            # Verify that all ledger files on stopped nodes exist on most up-to-date node
            # and are identical
            if most_up_to_date_node:
                longest_ledger_dir, _ = committed_ledger_dirs[
                    most_up_to_date_node.local_node_id
                ]
                for node_id, (committed_ledger_dir, _) in (
                    l
                    for l in committed_ledger_dirs.items()
                    if not l[0] == most_up_to_date_node.node_id
                ):
                    for ledger_file in os.listdir(committed_ledger_dir):
                        if ledger_file not in os.listdir(longest_ledger_dir):
                            raise Exception(
                                f"Ledger file on node {node_id} does not exist on most up-to-date node {most_up_to_date_node.local_node_id}: {ledger_file}"
                            )
                        if infra.path.compute_file_checksum(
                            os.path.join(longest_ledger_dir, ledger_file)
                        ) != infra.path.compute_file_checksum(
                            os.path.join(committed_ledger_dir, ledger_file)
                        ):
                            raise Exception(
                                f"Ledger file checksums between node {node_id} and most up-to-date node {most_up_to_date_node.node_id} did not match: {ledger_file}"
                            )

                LOG.success(
                    f"Verified ledger files consistency on all {len(self.nodes)} stopped nodes"
                )

        if fatal_error_found:
            if self.ignoring_shutdown_errors:
                LOG.warning("Ignoring shutdown errors")
            else:
                raise NodeShutdownError("Fatal error found during node shutdown")

    def join_node(
        self,
        node,
        lib_name,
        args,
        target_node=None,
        timeout=JOIN_TIMEOUT,
        **kwargs,
    ):
        self._add_node(
            node,
            lib_name,
            args,
            target_node,
            **kwargs,
        )

        primary, _ = self.find_primary()
        try:
            self.consortium.wait_for_node_to_exist_in_store(
                primary,
                node.node_id,
                timeout=timeout,
                node_status=(
                    NodeStatus.PENDING
                    if self.status == ServiceStatus.OPEN
                    else NodeStatus.TRUSTED
                ),
            )
        except TimeoutError as e:
            LOG.error(f"New pending node {node.node_id} failed to join the network")
            errors, _ = node.stop()
            self.nodes.remove(node)
            if errors:
                # Throw accurate exceptions if known errors found in
                for error in errors:
                    if "Quote does not contain known enclave measurement" in error:
                        raise CodeIdNotFound from e
                    if "StartupSnapshotIsOld" in error:
                        raise StartupSnapshotIsOld from e
            raise

    def trust_node(self, node, args, expected_status=NodeStatus.TRUSTED):
        primary, _ = self.find_primary()
        try:
            if self.status is ServiceStatus.OPEN:
                self.consortium.trust_node(
                    primary,
                    node.node_id,
                    expected_status,
                    timeout=ceil(args.join_timer * 2 / 1000),
                )
            # Here, quote verification has already been run when the node
            # was added as pending. Only wait for the join timer for the
            # joining node to retrieve network secrets.
            node.wait_for_node_to_join(timeout=ceil(args.join_timer * 2 / 1000))
        except (ValueError, TimeoutError):
            LOG.error(f"New trusted node {node.node_id} failed to join the network")
            node.stop()
            raise

        node.network_state = infra.node.NodeNetworkState.joined
        self.wait_for_all_nodes_to_commit(primary=primary)

    def retire_node(self, remote_node, node_to_retire):
        self.consortium.retire_node(remote_node, node_to_retire)
        self.nodes.remove(node_to_retire)

    def create_user(self, local_user_id, curve, record=True):
        infra.proc.ccall(
            self.key_generator,
            "--name",
            local_user_id,
            "--curve",
            f"{curve.name}",
            path=self.common_dir,
            log_output=False,
        ).check_returncode()

        with open(os.path.join(self.common_dir, f"{local_user_id}_cert.pem")) as c:
            service_user_id = infra.crypto.compute_cert_der_hash_hex_from_pem(c.read())
        new_user = UserInfo(
            local_user_id,
            service_user_id,
        )
        if record:
            self.users.append(new_user)

        return new_user

    def create_users(self, local_user_ids, curve):
        for local_user_id in local_user_ids:
            self.create_user(local_user_id, curve)

    def get_members(self):
        return self.consortium.members

    def get_joined_nodes(self):
        return [node for node in self.nodes if node.is_joined()]

    def wait_for_state(self, node, state, timeout=3):
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                with node.client(connection_timeout=timeout) as c:
                    r = c.get("/node/state")
                    if r.body.json()["state"] == state:
                        break
            except ConnectionRefusedError:
                pass
            time.sleep(0.1)
        else:
            raise TimeoutError(
                f"Timed out waiting for state {state} on node {node.node_id}"
            )
        if state == infra.node.State.PART_OF_NETWORK.value:
            self.status = ServiceStatus.OPEN

    def _wait_for_app_open(self, node, timeout=3):
        end_time = time.time() + timeout
        while time.time() < end_time:
            # As an operator, query a well-known /app endpoint to find out
            # if the app has been opened to users
            with node.client() as c:
                r = c.get("/app/commit")
                if not (r.status_code == http.HTTPStatus.NOT_FOUND.value):
                    return
                time.sleep(0.1)
        raise TimeoutError(f"Application frontend was not open after {timeout}s")

    def _get_node_by_service_id(self, node_id):
        return next((node for node in self.nodes if node.node_id == node_id), None)

    def find_primary(self, nodes=None, timeout=3, log_capture=None):
        """
        Find the identity of the primary in the network and return its identity
        and the current view.
        """
        primary_id = None
        view = None

        logs = []

        asked_nodes = nodes or self.get_joined_nodes()

        end_time = time.time() + timeout
        while time.time() < end_time:
            for node in asked_nodes:
                with node.client() as c:
                    try:
                        logs = []
                        res = c.get("/node/network", log_capture=logs)
                        assert res.status_code == http.HTTPStatus.OK.value, res

                        body = res.body.json()
                        view = body["current_view"]
                        primary_id = body["primary_id"]
                        if primary_id is not None:
                            break

                    except CCFConnectionException:
                        LOG.warning(
                            f"Could not successfully connect to node {node.local_node_id}. Retrying..."
                        )

            if primary_id is not None:
                break
            time.sleep(0.1)

        if primary_id is None:
            flush_info(logs, log_capture, 0)
            raise PrimaryNotFound

        flush_info(logs, log_capture, 0)

        return (self._get_node_by_service_id(primary_id), view)

    def find_backups(self, primary=None, timeout=3):
        if primary is None:
            primary, _ = self.find_primary(timeout=timeout)
        return [n for n in self.get_joined_nodes() if n != primary]

    def find_any_backup(self, primary=None, timeout=3):
        return random.choice(self.find_backups(primary=primary, timeout=timeout))

    def find_node_by_role(self, role=NodeRole.ANY):
        role_ = (
            random.choice([NodeRole.PRIMARY, NodeRole.BACKUP]) if NodeRole.ANY else role
        )
        if role_ == NodeRole.PRIMARY:
            return self.find_primary()[0]
        else:
            return self.find_any_backup()

    def find_random_node(self):
        return random.choice(self.get_joined_nodes())

    def find_nodes(self, timeout=3):
        primary, _ = self.find_primary(timeout=timeout)
        backups = self.find_backups(primary=primary, timeout=timeout)
        return primary, backups

    def find_primary_and_any_backup(self, timeout=3):
        primary, backups = self.find_nodes(timeout)
        backup = random.choice(backups)
        return primary, backup

    def wait_for_all_nodes_to_commit(self, primary=None, tx_id=None, timeout=10):
        """
        Wait for all nodes to have joined the network and committed all transactions
        executed on the primary.
        """
        if not (primary or tx_id):
            raise ValueError("Either a valid TxID or primary node should be specified")

        end_time = time.time() + timeout

        # If no TxID is specified, retrieve latest readable one
        if tx_id == None:
            while time.time() < end_time:
                with primary.client() as c:
                    resp = c.get(
                        "/node/network/nodes/self"
                    )  # Well-known read-only endpoint
                    tx_id = TxID(resp.view, resp.seqno)
                    if tx_id.valid():
                        break
                time.sleep(0.1)
            assert (
                tx_id.valid()
            ), f"Primary {primary.node_id} has not made any progress yet ({tx_id})"

        caught_up_nodes = []
        logs = {}
        while time.time() < end_time:
            caught_up_nodes = []
            for node in self.get_joined_nodes():
                with node.client() as c:
                    logs[node.node_id] = []
                    resp = c.get(
                        f"/node/local_tx?transaction_id={tx_id}",
                        log_capture=logs[node.node_id],
                    )
                    if resp.status_code != 200:
                        # Node may not have joined the network yet, try again
                        break
                    status = TxStatus(resp.body.json()["status"])
                    if status == TxStatus.Committed:
                        caught_up_nodes.append(node)
                    elif status == TxStatus.Invalid:
                        flush_info(logs[node.node_id], None, 0)
                        raise RuntimeError(
                            f"Node {node.node_id} reports transaction ID {tx_id} is invalid and will never be committed"
                        )
                    else:
                        pass

            if len(caught_up_nodes) == len(self.get_joined_nodes()):
                break
            time.sleep(0.1)

        for lines in logs.values():
            flush_info(lines, None, 0)
        assert len(caught_up_nodes) == len(
            self.get_joined_nodes()
        ), f"Only {len(caught_up_nodes)} (out of {len(self.get_joined_nodes())}) nodes have joined the network"

    def wait_for_node_commit_sync(self, timeout=3):
        """
        Wait for commit level to get in sync on all nodes. This is expected to
        happen once CFTR has been established, in the absence of new transactions.
        """
        end_time = time.time() + timeout
        while time.time() < end_time:
            commits = []
            for node in self.get_joined_nodes():
                with node.client() as c:
                    r = c.get("/node/commit")
                    assert r.status_code == http.HTTPStatus.OK.value
                    body = r.body.json()
                    commits.append(body["transaction_id"])
            if [commits[0]] * len(commits) == commits:
                break
            time.sleep(0.1)
        expected = [commits[0]] * len(commits)
        if expected != commits:
            for node in self.get_joined_nodes():
                r = c.get("/node/consensus")
                pprint.pprint(r.body.json())
        assert expected == commits, f"Multiple commit values: {commits}"

    def wait_for_new_primary(self, old_primary, nodes=None, timeout_multiplier=2):
        # We arbitrarily pick twice the election duration to protect ourselves against the somewhat
        # but not that rare cases when the first round of election fails (short timeout are particularly susceptible to this)
        timeout = self.election_duration * timeout_multiplier
        LOG.info(
            f"Waiting up to {timeout}s for a new primary different from {old_primary.local_node_id} ({old_primary.node_id}) to be elected..."
        )
        end_time = time.time() + timeout
        error = TimeoutError
        logs = []
        while time.time() < end_time:
            try:
                logs = []
                new_primary, new_term = self.find_primary(nodes=nodes, log_capture=logs)
                if new_primary.node_id != old_primary.node_id:
                    flush_info(logs, None)
                    LOG.info(
                        f"New primary is {new_primary.local_node_id} ({new_primary.node_id}) in term {new_term}"
                    )
                    return (new_primary, new_term)
            except PrimaryNotFound:
                error = PrimaryNotFound
            except Exception:
                pass
            time.sleep(0.1)
        flush_info(logs, None)
        raise error(f"A new primary was not elected after {timeout} seconds")

    def wait_for_new_primary_in(
        self, expected_node_ids, nodes=None, timeout_multiplier=2
    ):
        # We arbitrarily pick twice the election duration to protect ourselves against the somewhat
        # but not that rare cases when the first round of election fails (short timeout are particularly susceptible to this)
        timeout = self.election_duration * timeout_multiplier
        LOG.info(
            f"Waiting up to {timeout}s for a new primary in {expected_node_ids} to be elected..."
        )
        end_time = time.time() + timeout
        error = TimeoutError
        logs = []
        while time.time() < end_time:
            try:
                logs = []
                new_primary, new_term = self.find_primary(nodes=nodes, log_capture=logs)
                if new_primary.node_id in expected_node_ids:
                    flush_info(logs, None)
                    LOG.info(
                        f"New primary is {new_primary.local_node_id} ({new_primary.node_id}) in term {new_term}"
                    )
                    return (new_primary, new_term)
            except PrimaryNotFound:
                error = PrimaryNotFound
            except Exception:
                pass
            time.sleep(0.1)
        flush_info(logs, None)
        raise error(f"A new primary was not elected after {timeout} seconds")

    def wait_for_commit_proof(self, node, seqno, timeout=3):
        # Wait that the target seqno has a commit proof on a specific node.
        # This is achieved by first waiting for a commit over seqno, issuing
        # a write request and then waiting for a commit over that
        end_time = time.time() + timeout
        while time.time() < end_time:
            with node.client() as c:
                r = c.get("/node/commit")
                current_tx = TxID.from_str(r.body.json()["transaction_id"])
                if current_tx.seqno >= seqno:
                    with node.client(
                        self.consortium.get_any_active_member().local_id
                    ) as nc:
                        # Using update_state_digest here as a convenient write tx
                        # that is app agnostic
                        r = nc.post("/gov/ack/update_state_digest")
                        assert (
                            r.status_code == http.HTTPStatus.OK.value
                        ), f"Error ack/update_state_digest: {r}"
                        c.wait_for_commit(r)
                        return True
            time.sleep(0.1)
        raise TimeoutError(f"seqno {seqno} did not have commit proof after {timeout}s")

    def wait_for_snapshot_committed_for(self, seqno, timeout=3):
        # Check that snapshot exists for target seqno and if so, wait until
        # snapshot evidence has commit proof (= commit rule for snapshots)
        snapshot_evidence_seqno = None
        primary, _ = self.find_primary()
        for s in os.listdir(primary.get_snapshots()):
            if infra.node.get_snapshot_seqnos(s)[0] > seqno:
                snapshot_evidence_seqno = infra.node.get_snapshot_seqnos(s)[1]
        if snapshot_evidence_seqno is None:
            return False

        return self.wait_for_commit_proof(primary, snapshot_evidence_seqno, timeout)

    def get_committed_snapshots(self, node):
        # Wait for all available snapshot files to be committed before
        # copying snapshot directory, so that we always use the latest snapshot
        def wait_for_snapshots_to_be_committed(src_dir, list_src_dir_func, timeout=6):
            end_time = time.time() + timeout
            committed = True
            uncommitted_snapshots = []
            while time.time() < end_time:
                committed = True
                uncommitted_snapshots = []
                for f in list_src_dir_func(src_dir):
                    is_committed = infra.node.is_file_committed(f)
                    if not is_committed:
                        self.wait_for_commit_proof(
                            node, infra.node.get_snapshot_seqnos(f)[1]
                        )
                        uncommitted_snapshots.append(f)
                    committed &= is_committed
                if committed:
                    break
                time.sleep(0.1)
            if not committed:
                LOG.error(
                    f"Error: Not all snapshots were committed after {timeout}s in {src_dir}: {uncommitted_snapshots}"
                )
            return committed

        return node.get_committed_snapshots(wait_for_snapshots_to_be_committed)

    def _get_ledger_public_view_at(self, node, call, seqno, timeout):
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                return call(seqno)
            except Exception:
                self.consortium.create_and_withdraw_large_proposal(node)
                time.sleep(0.1)
        raise TimeoutError(
            f"Could not read transaction at seqno {seqno} from ledger {node.remote.ledger_paths()}"
        )

    def get_ledger_public_state_at(self, seqno, timeout=5):
        primary, _ = self.find_primary()
        return self._get_ledger_public_view_at(
            primary, primary.get_ledger_public_tables_at, seqno, timeout
        )

    def get_latest_ledger_public_state(self, timeout=5):
        primary, _ = self.find_primary()
        with primary.client() as nc:
            resp = nc.get("/node/commit")
            body = resp.body.json()
            tx_id = TxID.from_str(body["transaction_id"])
        return self._get_ledger_public_view_at(
            primary, primary.get_ledger_public_state_at, tx_id.seqno, timeout
        )


@contextmanager
def network(
    hosts,
    binary_directory=".",
    dbg_nodes=None,
    perf_nodes=None,
    pdb=False,
    txs=None,
    jwt_issuer=None,
    library_directory=".",
    init_partitioner=False,
    version=None,
):
    """
    Context manager for Network class.
    :param hosts: a list of hostnames (localhost or remote hostnames)
    :param binary_directory: the directory where CCF's binaries are located
    :param library_directory: the directory where CCF's libraries are located
    :param dbg_nodes: default: []. List of node id's that will not start (user is prompted to start them manually)
    :param perf_nodes: default: []. List of node ids that will run under perf record
    :param pdb: default: False. Debugger.
    :param txs: default: None. Transactions committed on that network.
    :return: a Network instance that can be used to create/access nodes, handle the genesis state (add members, create
    node.json), and stop all the nodes that belong to the network
    """
    if dbg_nodes is None:
        dbg_nodes = []
    if perf_nodes is None:
        perf_nodes = []

    net = Network(
        hosts=hosts,
        binary_dir=binary_directory,
        library_dir=library_directory,
        dbg_nodes=dbg_nodes,
        perf_nodes=perf_nodes,
        txs=txs,
        jwt_issuer=jwt_issuer,
        init_partitioner=init_partitioner,
        version=version,
    )
    try:
        yield net
    except Exception:
        # Don't try to verify txs on Exception path
        net.txs = None

        if pdb:
            import pdb

            pdb.set_trace()
        else:
            raise
    finally:
        LOG.info("Stopping network")
        net.stop_all_nodes(skip_verification=True)
        if init_partitioner:
            net.partitioner.cleanup()
