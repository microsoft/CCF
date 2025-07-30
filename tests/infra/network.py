# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import time

from contextlib import contextmanager
from enum import Enum, IntEnum, auto
from infra.clients import flush_info
import infra.member
import infra.path
import infra.proc
import infra.service_load
import infra.node
import infra.consortium
import infra.e2e_args
import ccf.ledger
from infra.tx_status import TxStatus
from ccf.tx_id import TxID
import random
from dataclasses import dataclass
import http
import pprint
import functools
import re
import hashlib
from datetime import datetime, timedelta, timezone
from infra.consortium import slurp_file
from collections import deque


from loguru import logger as LOG

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

# JOIN_TIMEOUT should be greater than the worst case quote verification time (~ 25 secs)
JOIN_TIMEOUT = 40

# If it takes a node n seconds to call an election, how long should we wait for an election to succeed?
DEFAULT_TIMEOUT_MULTIPLIER = 15

COMMON_FOLDER = "common"


class NodeRole(Enum):
    ANY = auto()
    PRIMARY = auto()
    BACKUP = auto()


class ServiceStatus(Enum):
    OPENING = "Opening"
    OPEN = "Open"
    RECOVERING = "Recovering"
    CLOSED = "Closed"


class EllipticCurve(IntEnum):
    secp384r1 = 0
    secp256r1 = 1

    def next(self):
        return EllipticCurve((self.value + 1) % len(EllipticCurve))


class PrimaryNotFound(Exception):
    pass


class MeasurementNotFound(Exception):
    pass


class HostDataNotFound(Exception):
    pass


class UVMEndorsementsNotAuthorised(Exception):
    pass


class StartupSeqnoIsOld(Exception):
    pass


class CollateralFetchTimeout(Exception):
    pass


class ServiceCertificateInvalid(Exception):
    pass


class NetworkShutdownError(Exception):
    def __init__(self, msg, errors=None):
        super().__init__(msg)
        self.errors = errors


def get_common_folder_name(workspace, label):
    return os.path.join(workspace, f"{label}_{COMMON_FOLDER}")


@dataclass
class UserInfo:
    local_id: int
    service_id: str
    cert_path: str
    key_path: str


DEFAULT_TAIL_LINES_LEN = 10


def log_errors(
    out_path,
    err_path,
    tail_lines_len=DEFAULT_TAIL_LINES_LEN,
    ignore_error_patterns=None,
):
    error_filter = ["[fail ]", "[fatal]", "Atom leak", "atom leakage"]
    error_lines = []
    try:
        tail_lines = deque(maxlen=tail_lines_len)
        with open(out_path, "r", errors="replace", encoding="utf-8") as lines:
            for line_no, line in enumerate(lines):
                stripped_line = line.rstrip()
                tail_lines.append(stripped_line)
                if any(x in stripped_line for x in error_filter):
                    ignore = False
                    if ignore_error_patterns is not None:
                        for pattern in ignore_error_patterns:
                            if pattern in stripped_line:
                                ignore = True
                                break
                    if not ignore:
                        LOG.error(f"{out_path}:{line_no+1}: {stripped_line}")
                        error_lines.append(stripped_line)
        if error_lines:
            LOG.info(
                "{} errors found, printing end of output for context:", len(error_lines)
            )
            for line in tail_lines:
                LOG.info(line)
    except IOError:
        LOG.exception("Could not check output {} for errors".format(out_path))

    fatal_error_lines = []
    try:
        with open(err_path, "r", errors="replace", encoding="utf-8") as lines:
            fatal_error_lines = [
                line
                for line in lines.readlines()
                if not line.startswith("[get_qpl_handle ")
            ]
            if fatal_error_lines:
                LOG.error(f"Contents of {err_path}:\n{''.join(fatal_error_lines)}")
    except IOError:
        LOG.exception("Could not read err output {}".format(err_path))

    return error_lines, fatal_error_lines


class Network:
    KEY_GEN = "keygenerator.sh"
    SHARE_SCRIPT = "submit_recovery_share.sh"
    node_args_to_forward = [
        "log_level",
        "sig_tx_interval",
        "sig_ms_interval",
        "election_timeout_ms",
        "consensus_update_timeout_ms",
        "consensus",
        "log_format_json",
        "constitution",
        "join_timer_s",
        "worker_threads",
        "ledger_chunk_bytes",
        "subject_alt_names",
        "snapshot_tx_interval",
        "max_open_sessions",
        "max_open_sessions_hard",
        "forwarding_timeout_ms",
        "jwt_key_refresh_interval_s",
        "common_read_only_ledger_dir",
        "curve_id",
        "initial_node_cert_validity_days",
        "initial_service_cert_validity_days",
        "maximum_node_certificate_validity_days",
        "maximum_service_certificate_validity_days",
        "config_file",
        "ubsan_options",
        "previous_service_identity_file",
        "acme",
        "snp_endorsements_servers",
        "node_to_node_message_limit",
        "historical_cache_soft_limit",
        "tick_ms",
        "max_msg_size_bytes",
        "snp_security_policy_file",
        "snp_uvm_endorsements_file",
        "snp_endorsements_file",
        "subject_name",
        "idle_connection_timeout_s",
        "enable_local_sealing",
        "previous_sealed_ledger_secret_location",
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
        service_load=None,
        node_data_json_file=None,
        next_node_id=0,
    ):
        # Map of node id to dict of node arg to override value
        # for example, to set the election timeout to 2s for node 3:
        # per_node_args_override = {3: {"election_timeout_ms": 2000}}
        self.per_node_args_override = {}

        if existing_network is None:
            self.consortium = None
            self.users = []
            self.hosts = hosts
            self.next_node_id = next_node_id
            self.txs = txs
            self.jwt_issuer = jwt_issuer
            self.service_load = service_load
            self.recovery_count = 0
        else:
            self.consortium = existing_network.consortium
            self.users = existing_network.users
            self.next_node_id = existing_network.next_node_id
            self.txs = existing_network.txs
            self.jwt_issuer = existing_network.jwt_issuer
            self.hosts = infra.e2e_args.nodes(
                existing_network.args, len(existing_network.nodes)
            )
            self.service_load = None
            if existing_network.service_load:
                self.service_load = existing_network.service_load
                self.service_load.set_network(self)
            self.recovery_count = existing_network.recovery_count

        self.ignoring_shutdown_errors = False
        self.ignore_error_patterns = []
        self.nodes = []
        self.status = ServiceStatus.CLOSED
        self.binary_dir = binary_dir
        self.library_dir = library_dir
        self.common_dir = None
        self.election_duration = None
        self.observed_election_duration = None
        self.key_generator = os.path.join(binary_dir, self.KEY_GEN)
        self.share_script = os.path.join(binary_dir, self.SHARE_SCRIPT)
        if not os.path.isfile(self.key_generator):
            raise FileNotFoundError(
                f"Could not find key generator script at '{self.key_generator}' - is binary directory set correctly?"
            )
        self.dbg_nodes = dbg_nodes
        self.perf_nodes = perf_nodes
        self.version = version
        self.args = None
        self.service_certificate_valid_from = None
        self.service_certificate_validity_days = None

        # Requires admin privileges
        self.partitioner = (
            infra.partitions.Partitioner(self) if init_partitioner else None
        )

        try:
            os.remove("/tmp/vscode-gdb.sh")
        except FileNotFoundError:
            pass

        for host in self.hosts:
            self.create_node(
                host, version=self.version, node_data_json_file=node_data_json_file
            )

    def _get_next_local_node_id(self):
        next_node_id = self.next_node_id
        self.next_node_id += 1
        return next_node_id

    def create_node(self, host, binary_dir=None, library_dir=None, **kwargs):
        node_id = self._get_next_local_node_id()
        debug = (
            (str(node_id) in self.dbg_nodes) if self.dbg_nodes is not None else False
        )
        perf = (
            (str(node_id) in self.perf_nodes) if self.perf_nodes is not None else False
        )

        if isinstance(host, str):
            interface = infra.interfaces.RPCInterface()
            interface.parse_from_str(host)
            host = infra.interfaces.HostSpec(
                rpc_interfaces={infra.interfaces.PRIMARY_RPC_INTERFACE: interface}
            )

        node = infra.node.Node(
            node_id,
            host,
            binary_dir or self.binary_dir,
            library_dir or self.library_dir,
            debug,
            perf,
            **kwargs,
        )
        self.nodes.append(node)
        return node

    def _setup_node(
        self,
        node,
        lib_name,
        args,
        target_node=None,
        recovery=False,
        ledger_dir=None,
        copy_ledger=True,
        read_only_ledger_dirs=None,
        from_snapshot=True,
        snapshots_dir=None,
        **kwargs,
    ):
        # Contact primary if no target node is set
        primary, _ = self.find_primary(
            timeout=args.ledger_recovery_timeout if recovery else 10
        )
        target_node = target_node or primary
        LOG.info(f"Joining from target node {target_node.local_node_id}")

        committed_ledger_dirs = read_only_ledger_dirs or []
        current_ledger_dir = ledger_dir
        read_only_snapshots_dir = None

        # Note: Copy snapshot before ledger as retrieving the latest snapshot may require
        # to produce more ledger entries
        if from_snapshot:
            # Only retrieve snapshot from primary if the snapshot directory is not specified
            if snapshots_dir is None:
                read_only_snapshots_dir = self.get_committed_snapshots(primary)
            if os.listdir(snapshots_dir) or os.listdir(read_only_snapshots_dir):
                LOG.info(
                    f"Joining from snapshot directories: {snapshots_dir},{read_only_snapshots_dir}"
                )
            else:
                LOG.warning(
                    f"Attempting to join from snapshot but {snapshots_dir},{read_only_snapshots_dir} are empty: defaulting to complete replay of transaction history"
                )
        else:
            LOG.info(
                "Joining without snapshot: complete transaction history will be replayed"
            )

        if not committed_ledger_dirs and copy_ledger:
            LOG.info(f"Copying ledger from target node {target_node.local_node_id}")
            current_ledger_dir, committed_ledger_dirs = target_node.get_ledger()

        # Note: temporary fix until second snapshot directory is ported to 2.x branch
        if not node.version_after("ccf-2.0.3") and read_only_snapshots_dir is not None:
            snapshots_dir = read_only_snapshots_dir

        node.prepare_join(
            lib_name=lib_name,
            workspace=args.workspace,
            label=args.label,
            common_dir=self.common_dir,
            target_rpc_address=target_node.get_public_rpc_address(),
            snapshots_dir=snapshots_dir,
            read_only_snapshots_dir=read_only_snapshots_dir,
            ledger_dir=current_ledger_dir,
            read_only_ledger_dirs=committed_ledger_dirs,
            **kwargs,
        )

    def _add_node(
        self,
        node,
        lib_name,
        args,
        target_node=None,
        recovery=False,
        ledger_dir=None,
        copy_ledger=True,
        read_only_ledger_dirs=None,
        from_snapshot=True,
        snapshots_dir=None,
        **kwargs,
    ):
        self._setup_node(
            node,
            lib_name,
            args,
            target_node,
            recovery,
            ledger_dir,
            copy_ledger,
            read_only_ledger_dirs,
            from_snapshot,
            snapshots_dir,
            **kwargs,
        )
        node.complete_join()

        # If the network is opening or recovering, nodes are trusted without consortium approval
        if (
            self.status == ServiceStatus.OPENING
            or self.status == ServiceStatus.RECOVERING
        ):
            try:
                node.wait_for_node_to_join(timeout=JOIN_TIMEOUT)
            except TimeoutError:
                LOG.error(f"New node {node.local_node_id} failed to join the network")
                raise

    def _start_all_nodes(
        self,
        args,
        recovery=False,
        ledger_dir=None,
        read_only_ledger_dirs=None,
        snapshots_dir=None,
        **kwargs,
    ):
        self.args = args
        hosts = self.hosts

        if not args.package:
            raise ValueError("A package name must be specified.")

        self.status = (
            ServiceStatus.OPENING if not recovery else ServiceStatus.RECOVERING
        )
        LOG.debug(f"Opening CCF service on {hosts}")

        forwarded_args = {
            arg: getattr(args, arg, None)
            for arg in infra.network.Network.node_args_to_forward
        }

        for i, node in enumerate(self.nodes):
            forwarded_args_with_overrides = forwarded_args.copy()
            forwarded_args_with_overrides.update(self.per_node_args_override.get(i, {}))
            try:
                if i == 0:
                    if not recovery:
                        node.start(
                            lib_name=args.package,
                            workspace=args.workspace,
                            label=args.label,
                            common_dir=self.common_dir,
                            ledger_dir=ledger_dir,
                            members_info=self.consortium.get_members_info(),
                            **forwarded_args_with_overrides,
                            **kwargs,
                        )
                    else:
                        node.recover(
                            lib_name=args.package,
                            workspace=args.workspace,
                            label=args.label,
                            common_dir=self.common_dir,
                            ledger_dir=ledger_dir,
                            read_only_ledger_dirs=read_only_ledger_dirs,
                            snapshots_dir=snapshots_dir,
                            **forwarded_args_with_overrides,
                            **kwargs,
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
                        from_snapshot=snapshots_dir is not None,
                        read_only_ledger_dirs=read_only_ledger_dirs,
                        snapshots_dir=snapshots_dir,
                        **forwarded_args_with_overrides,
                        **kwargs,
                    )
            except Exception:
                LOG.exception(f"Failed to start node {node.local_node_id}")
                raise

        self.election_duration = args.election_timeout_ms / 1000
        # After an election timeout, we need some additional roundtrips to complete before
        # the nodes _observe_ that an election has occurred
        self.observed_election_duration = self.election_duration + 1

        LOG.info("All nodes started")

        # Here, recovery nodes might still be catching up, and possibly swamp
        # the current primary which would not be able to serve user requests
        primary, _ = self.find_primary(
            timeout=args.ledger_recovery_timeout if recovery else 10
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
        cmd = ["ln", "-s"]
        cmd += [self.key_generator, self.common_dir]
        assert (
            infra.proc.ccall(*cmd).returncode == 0
        ), f"Could not symlink {self.KEY_GEN} to {self.common_dir}"

    def start(self, args, **kwargs):
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
        assert (
            mc >= args.initial_operator_provisioner_count + args.initial_operator_count
        ), f"Not enough members ({mc}) for the set amount of operator provisioners and operators"

        if args.initial_recovery_owner_count > 0:
            assert (
                mc
                >= args.initial_recovery_participant_count
                + args.initial_recovery_owner_count
            ), f"Not enough members ({mc}) for the set amount of recovery participants and owners ({args.initial_recovery_participant_count + args.initial_recovery_owner_count})"

        self.consortium = infra.consortium.Consortium(
            self.common_dir,
            self.key_generator,
            self.share_script,
            args.consensus,
            gov_api_version=args.gov_api_version,
        )

        for i in range(mc):
            member_data = None
            if i < args.initial_operator_provisioner_count:
                member_data = {"is_operator_provisioner": True}
            elif (
                i
                < args.initial_operator_provisioner_count + args.initial_operator_count
            ):
                member_data = {"is_operator": True}
            recovery_role = infra.member.RecoveryRole.NonParticipant
            if i < args.initial_recovery_participant_count:
                recovery_role = infra.member.RecoveryRole.Participant
            elif (
                i
                < args.initial_recovery_participant_count
                + args.initial_recovery_owner_count
            ):
                recovery_role = infra.member.RecoveryRole.Owner

            self.consortium.add_member(
                self.consortium.generate_new_member(
                    curve=args.participants_curve,
                    recovery_role=recovery_role,
                    member_data=member_data,
                )
            )

        set_authenticate_session = kwargs.pop("set_authenticate_session", None)
        if set_authenticate_session is not None:
            self.consortium.set_authenticate_session(set_authenticate_session)

        primary = self._start_all_nodes(args, **kwargs)
        self.wait_for_all_nodes_to_commit(primary=primary)
        LOG.success("All nodes joined network")

        # Initial recovery threshold is derived by the service from the number of recovery members.
        # Don't reproduce that here, just ask the service what it chose
        self.consortium.update_recovery_threshold_from_node(primary)

    def open(self, args):
        def get_target_node(args, primary):
            # HTTP/2 does not currently support forwarding
            if args.http2:
                return primary
            return self.find_random_node()

        primary, _ = self.find_primary()
        self.consortium.activate(get_target_node(args, primary))

        if args.js_app_bundle:
            self.consortium.set_js_app_from_dir(
                remote_node=get_target_node(args, primary),
                bundle_path=args.js_app_bundle,
            )

        for path in args.jwt_issuer:
            self.consortium.set_jwt_issuer(
                remote_node=get_target_node(args, primary), json_path=path
            )

        if self.jwt_issuer:
            self.jwt_issuer.register(self)

        initial_users = [
            f"user{user_id}" for user_id in list(range(max(0, args.initial_user_count)))
        ]
        self.create_users(initial_users, args.participants_curve)

        self.consortium.add_users_and_transition_service_to_open(
            get_target_node(args, primary), initial_users
        )
        self.status = ServiceStatus.OPEN
        LOG.info(f"Initial set of users added: {len(initial_users)}")

        for node in self.get_joined_nodes():
            self._wait_for_app_open(node, timeout=args.ledger_recovery_timeout)

        LOG.success("***** Network is now open *****")
        if self.service_load:
            self.service_load.begin(self)

    def start_and_open(self, args, **kwargs):
        self.start(args, **kwargs)
        self.open(args)

    def start_in_recovery(
        self,
        args,
        ledger_dir=None,
        committed_ledger_dirs=None,
        snapshots_dir=None,
        common_dir=None,
        set_authenticate_session=None,
        **kwargs,
    ):
        """
        Starts a CCF network in recovery mode.
        :param args: command line arguments to configure the CCF nodes.
        :param ledger_dir: ledger directory to recover from.
        :param snapshots_dir: snapshot directory to recover from.
        :param common_dir: common directory containing member and user keys and certs.
        """
        self.common_dir = common_dir or get_common_folder_name(
            args.workspace, args.label
        )
        committed_ledger_dirs = committed_ledger_dirs or []

        primary = self._start_all_nodes(
            args,
            recovery=True,
            ledger_dir=ledger_dir,
            read_only_ledger_dirs=committed_ledger_dirs,
            snapshots_dir=snapshots_dir,
            **kwargs,
        )

        # If a common directory was passed in, initialise the consortium from it
        if not self.consortium and common_dir is not None:
            with primary.api_versioned_client(
                api_version=args.gov_api_version,
            ) as c:
                self.consortium = infra.consortium.Consortium(
                    common_dir,
                    self.key_generator,
                    self.share_script,
                    args.consensus,
                    gov_api_version=args.gov_api_version,
                )
                for f in os.listdir(self.common_dir):
                    if re.search("member(.*)_cert.pem", f) is not None:
                        local_id = f.split("_")[0]
                        recovery_role = (
                            infra.member.RecoveryRole.Participant
                            if os.path.isfile(
                                os.path.join(
                                    self.common_dir, f"{local_id}_enc_privk.pem"
                                )
                            )
                            else infra.member.RecoveryRole.NonParticipant
                        )

                        new_member = self.consortium.generate_existing_member(
                            local_id, recovery_role
                        )

                        r = c.get(f"/gov/service/members/{new_member.service_id}")
                        assert r.status_code == 200
                        member_info = r.body.json()
                        assert member_info["memberId"] == new_member.service_id
                        assert (
                            infra.member.RecoveryRole(member_info["recoveryRole"])
                            == new_member.recovery_role
                        )
                        new_member.member_data = member_info["memberData"]
                        if (
                            infra.member.MemberStatus(member_info["status"])
                            == infra.member.MemberStatus.ACTIVE
                        ):
                            new_member.set_active()

                        self.consortium.add_member(new_member)
                        LOG.info(
                            f"Successfully recovered member {local_id}: {new_member.service_id}"
                        )

            # Override locally-computed threshold to match whatever was retrieved from service
            self.consortium.update_recovery_threshold_from_node(primary)

        if set_authenticate_session is not None:
            self.consortium.set_authenticate_session(set_authenticate_session)

        for node in self.get_joined_nodes():
            self.wait_for_state(
                node,
                infra.node.State.PART_OF_PUBLIC_NETWORK.value,
                timeout=args.ledger_recovery_timeout,
            )
        # Catch-up in recovery can take a long time, so extend this timeout
        self.wait_for_all_nodes_to_commit(primary=primary, timeout=20)
        LOG.success("All nodes joined public network")

    def recover(
        self,
        args,
        expected_recovery_count=None,
        via_recovery_owner=False,
        via_local_sealing=False,
    ):
        """
        Recovers a CCF network previously started in recovery mode.
        :param args: command line arguments to configure the CCF nodes.
        """
        random_node = self.find_random_node()
        self.consortium.activate(random_node)
        expected_status = (
            ServiceStatus.RECOVERING
            if random_node.version_after("ccf-2.0.0-rc3")
            else ServiceStatus.OPENING
        )
        self.consortium.check_for_service(
            self.find_random_node(), status=expected_status
        )
        self.wait_for_all_nodes_to_be_trusted(self.find_random_node())

        # The new service may be running a newer version of the constitution,
        # so we make sure that we're running the right one.
        self.consortium.set_constitution(random_node, args.constitution)

        prev_service_identity = None
        if args.previous_service_identity_file:
            prev_service_identity = slurp_file(args.previous_service_identity_file)

        self.consortium.transition_service_to_open(
            self.find_random_node(),
            previous_service_identity=prev_service_identity,
        )

        if via_local_sealing:
            pass
        elif via_recovery_owner:
            self.consortium.recover_with_owner_share(self.find_random_node())
        else:
            self.consortium.recover_with_shares(self.find_random_node())

        for node in self.get_joined_nodes():
            self.wait_for_state(
                node,
                infra.node.State.PART_OF_NETWORK.value,
                timeout=args.ledger_recovery_timeout,
            )
            self._wait_for_app_open(node)

        self.recovery_count = expected_recovery_count or self.recovery_count + 1
        self.consortium.check_for_service(
            self.find_random_node(),
            ServiceStatus.OPEN,
            recovery_count=self.recovery_count,
        )
        LOG.success("***** Recovered network is now open *****")

    def ignore_errors_on_shutdown(self):
        self.ignoring_shutdown_errors = True

    def ignore_error_pattern_on_shutdown(self, pattern):
        self.ignore_error_patterns.append(pattern)

    def check_ledger_files_identical(self, read_recovery_ledger_files=False):
        # Note: Should be called on stopped service
        # Verify that all ledger files on stopped nodes exist on most up-to-date node
        # and are identical

        def list_files_in_dirs_with_checksums(dirs):
            return sorted(
                [
                    (f, infra.path.compute_file_checksum(os.path.join(d, f)))
                    for d in dirs
                    for f in os.listdir(d)
                    if f.endswith(ccf.ledger.COMMITTED_FILE_SUFFIX)
                    or (
                        read_recovery_ledger_files
                        and f.endswith(ccf.ledger.RECOVERY_FILE_SUFFIX)
                        and ccf.ledger.COMMITTED_FILE_SUFFIX in f
                    )
                ],
                key=lambda x: ccf.ledger.range_from_filename(x[0])[0],
            )

        longest_ledger_files = None
        longest_ledger_node = None
        longest_ledger_seqno = 0
        for node in self.nodes:
            if node.network_state != infra.node.NodeNetworkState.stopped:
                raise RuntimeError(
                    f"Node {node.node_id} should be stopped before verifying ledger consistency"
                )

            if node.remote is None:
                continue

            ledger_paths = node.remote.ledger_paths()

            # Check that at least the main ledger directory, created by
            # the node on startup, exists
            if not os.path.isdir(ledger_paths[0]):
                return

            ledger_files = list_files_in_dirs_with_checksums(ledger_paths)
            if not ledger_files:
                continue

            last_ledger_seqno = ccf.ledger.range_from_filename(ledger_files[-1][0])[1]
            ledger_files = set(ledger_files)

            if last_ledger_seqno > longest_ledger_seqno:
                assert longest_ledger_files is None or longest_ledger_files.issubset(
                    ledger_files
                ), f"Ledger files on node {longest_ledger_node.local_node_id} do not match files on node {node.local_node_id}: {longest_ledger_files}, expected subset of {ledger_files}, diff: {ledger_files - longest_ledger_files}"
                longest_ledger_files = ledger_files
                longest_ledger_node = node
                longest_ledger_seqno = last_ledger_seqno
            else:
                assert ledger_files.issubset(
                    longest_ledger_files
                ), f"Ledger files on node {node.local_node_id} do not match files on node {longest_ledger_node.local_node_id}: {ledger_files}, expected subset of {longest_ledger_files}, diff: {longest_ledger_files - ledger_files}"

        if longest_ledger_files:
            LOG.info(
                f"Verified {len(longest_ledger_files)} ledger files consistency on all {len(self.nodes)} stopped nodes"
            )

    def stop_all_nodes(
        self,
        skip_verification=False,
        verbose_verification=False,
        accept_ledger_diff=False,
        **kwargs,
    ):
        if not skip_verification and self.txs is not None:
            LOG.info("Verifying that all committed txs can be read before shutdown")
            log_capture = []
            try:
                self.txs.verify(network=self, log_capture=log_capture)
                self.txs.verify_range(log_capture=log_capture)
            except:
                flush_info(log_capture, None)
                raise
            else:
                if verbose_verification:
                    flush_info(log_capture, None)

        fatal_error_found = False

        if len(self.ignore_error_patterns) > 0:
            LOG.warning("Ignoring error patterns on shutdown:")
            for pattern in self.ignore_error_patterns:
                LOG.warning(f"  {pattern}")

        node_errors = {}
        for node in self.nodes:
            node.stop()
            out_path, err_path = node.get_logs()
            if out_path is not None and err_path is not None:
                _, fatal_errors = log_errors(
                    out_path, err_path, ignore_error_patterns=self.ignore_error_patterns
                )
            else:
                fatal_errors = []
            node_errors[node.local_node_id] = fatal_errors
            if fatal_errors:
                fatal_error_found = True

        LOG.info("All nodes stopped")
        if not accept_ledger_diff:
            self.check_ledger_files_identical(**kwargs)

        if fatal_error_found:
            if self.ignoring_shutdown_errors:
                LOG.warning("Ignoring shutdown errors")
            else:
                raise NetworkShutdownError(
                    "Fatal error found during node shutdown", node_errors
                )

    def setup_join_node(
        self,
        node,
        lib_name,
        args,
        target_node=None,
        **kwargs,
    ):
        forwarded_args = {
            arg: getattr(args, arg, None)
            for arg in infra.network.Network.node_args_to_forward
        }
        forwarded_args.update(kwargs)
        self._setup_node(node, lib_name, args, target_node, **forwarded_args)

    def run_join_node(
        self,
        node,
        timeout=JOIN_TIMEOUT,
        stop_on_error=False,
        wait_for_node_in_store=True,
    ):
        node.complete_join()
        if wait_for_node_in_store:
            primary, _ = self.find_primary()
            try:
                self.wait_for_node_in_store(
                    primary,
                    node.node_id,
                    node_status=(
                        ccf.ledger.NodeStatus.PENDING
                        if self.status == ServiceStatus.OPEN
                        else ccf.ledger.NodeStatus.TRUSTED
                    ),
                    timeout=timeout,
                )
            except TimeoutError as e:
                LOG.error(f"New pending node {node.node_id} failed to join the network")
                has_stopped = node.remote.check_done()
                if stop_on_error:
                    assert has_stopped, "Node should have stopped"
                node.stop()
                out_path, err_path = node.get_logs()
                if out_path is not None and err_path is not None:
                    errors, _ = log_errors(out_path, err_path)
                else:
                    errors = []
                self.nodes.remove(node)
                if errors:
                    giving_up_fetching = re.compile(
                        r"Giving up retrying fetching attestation endorsements from .* after (\d+) attempts"
                    )
                    # Throw accurate exceptions if known errors found in
                    for error in errors:
                        if "Quote does not contain known enclave measurement" in error:
                            raise MeasurementNotFound from e
                        if "Quote host data is not authorised" in error:
                            raise HostDataNotFound from e
                        if "UVM endorsements are not authorised" in error:
                            raise UVMEndorsementsNotAuthorised from e
                        if "StartupSeqnoIsOld" in error:
                            raise StartupSeqnoIsOld(has_stopped) from e
                        if "invalid cert on handshake" in error:
                            raise ServiceCertificateInvalid from e
                        match = giving_up_fetching.search(error)
                        if match:
                            raise CollateralFetchTimeout(
                                has_stopped, int(match.group(1))
                            ) from e
                raise

    def join_node(
        self,
        node,
        lib_name,
        args,
        target_node=None,
        timeout=JOIN_TIMEOUT,
        stop_on_error=False,
        **kwargs,
    ):
        self.setup_join_node(node, lib_name, args, target_node, **kwargs)
        self.run_join_node(node, timeout, stop_on_error)

    def trust_node(
        self,
        node,
        args,
        valid_from=None,
        validity_period_days=None,
        no_wait=False,
        timeout=None,
    ):
        primary, _ = self.find_primary()
        try:
            if self.status is ServiceStatus.OPEN:
                valid_from = valid_from or datetime.now(timezone.utc)
                # Note: Timeout is function of the ledger size here since
                # the commit of the trust_node proposal may rely on the new node
                # catching up (e.g. adding 1 node to a 1-node network).
                self.consortium.trust_node(
                    primary,
                    node.node_id,
                    valid_from=valid_from,
                    validity_period_days=validity_period_days,
                    timeout=args.ledger_recovery_timeout,
                )
            if not no_wait:
                # The main endorsed RPC interface is only open once the node
                # has caught up and observed commit on the service open transaction.
                node.wait_for_node_to_join(
                    timeout=timeout or args.ledger_recovery_timeout
                )
        except (ValueError, TimeoutError):
            LOG.error(f"New trusted node {node.node_id} failed to join the network")
            node.stop()
            raise

        node.network_state = infra.node.NodeNetworkState.joined
        node.set_certificate_validity_period(
            valid_from,
            validity_period_days or args.maximum_node_certificate_validity_days,
        )
        if not no_wait:
            self.wait_for_all_nodes_to_commit(primary=primary)

    def retire_node(self, remote_node, node_to_retire, timeout=10):
        pending = self.consortium.retire_node(
            remote_node, node_to_retire, timeout=timeout
        )
        if remote_node == node_to_retire:
            remote_node, _ = self.wait_for_new_primary(remote_node)
        if remote_node.version_after("ccf-2.0.4") and not pending:
            end_time = time.time() + timeout
            r = None
            while time.time() < end_time:
                try:
                    with remote_node.client(connection_timeout=timeout) as c:
                        r = c.get("/node/network/removable_nodes").body.json()
                        if node_to_retire.node_id in {n["node_id"] for n in r["nodes"]}:
                            check_commit = infra.checker.Checker(c)
                            r = c.delete(
                                f"/node/network/nodes/{node_to_retire.node_id}"
                            )
                            check_commit(r)
                            break
                        else:
                            r = c.get(
                                f"/node/network/nodes/{node_to_retire.node_id}"
                            ).body.json()
                except ConnectionRefusedError:
                    pass
                time.sleep(0.1)
            else:
                raise TimeoutError(f"Timed out waiting for node to become removed: {r}")

        self.nodes.remove(node_to_retire)

    def replace_stopped_node(
        self,
        node_to_retire,
        node_to_add,
        args,
        valid_from=None,
        validity_period_days=None,
        timeout=5,
        statistics=None,
    ):
        primary, _ = self.find_primary()
        try:
            if self.status is ServiceStatus.OPEN:
                valid_from = valid_from or datetime.now(timezone.utc)
                # Note: Timeout is function of the ledger size here since
                # the commit of the trust_node proposal may rely on the new node
                # catching up (e.g. adding 1 node to a 1-node network).
                if statistics is not None:
                    statistics["node_replacement_governance_start"] = (
                        datetime.now().isoformat()
                    )
                self.consortium.replace_node(
                    primary,
                    node_to_retire,
                    node_to_add,
                    valid_from=valid_from,
                    validity_period_days=validity_period_days,
                    timeout=args.ledger_recovery_timeout,
                )
                if statistics is not None:
                    statistics["node_replacement_governance_committed"] = (
                        datetime.now().isoformat()
                    )
        except (ValueError, TimeoutError):
            LOG.error(
                f"Failed to replace {node_to_retire.node_id} with {node_to_add.node_id}"
            )
            node_to_add.stop()
            raise

        node_to_add.network_state = infra.node.NodeNetworkState.joined
        end_time = time.time() + timeout
        r = None
        while time.time() < end_time:
            try:
                with primary.client() as c:
                    r = c.get("/node/network/removable_nodes").body.json()
                    if node_to_retire.node_id in {n["node_id"] for n in r["nodes"]}:
                        check_commit = infra.checker.Checker(c)
                        r = c.delete(f"/node/network/nodes/{node_to_retire.node_id}")
                        check_commit(r)
                        break
                    else:
                        r = c.get(
                            f"/node/network/nodes/{node_to_retire.node_id}"
                        ).body.json()
            except ConnectionRefusedError:
                pass
            time.sleep(0.1)
        else:
            raise TimeoutError(f"Timed out waiting for node to become removed: {r}")
        if statistics is not None:
            statistics["old_node_removal_committed"] = datetime.now().isoformat()
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

        cert_path = os.path.join(self.common_dir, f"{local_user_id}_cert.pem")
        with open(cert_path, encoding="utf-8") as c:
            service_user_id = infra.crypto.compute_cert_der_hash_hex_from_pem(c.read())
        key_path = os.path.join(self.common_dir, f"{local_user_id}_privk.pem")
        new_user = UserInfo(local_user_id, service_user_id, cert_path, key_path)
        if record:
            self.users.append(new_user)

        return new_user

    def create_users(self, local_user_ids, curve):
        for local_user_id in local_user_ids:
            self.create_user(local_user_id, curve)

    def get_members(self):
        return self.consortium.members

    def get_joined_nodes(self):
        return [
            node
            for node in self.nodes
            if node.is_joined() and not (node.is_stopped() or node.suspended)
        ]

    def get_stopped_nodes(self):
        return [node for node in self.nodes if node.is_stopped()]

    def get_live_nodes(self):
        return [node for node in self.nodes if not node.is_stopped()]

    def get_f(self):
        return infra.e2e_args.max_f(self.args, len(self.nodes))

    def wait_for_state(self, node, state, timeout=3):
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                with node.client(connection_timeout=timeout) as c:
                    r = c.get("/node/state").body.json()
                    if r["state"] == state:
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
        logs = []
        while time.time() < end_time:
            # As an operator, query a well-known /app endpoint to find out
            # if the app has been opened to users
            with node.client() as c:
                logs = []
                r = c.get("/app/commit", log_capture=logs)
                if not (r.status_code == http.HTTPStatus.NOT_FOUND.value):
                    flush_info(logs, None)
                    return
                time.sleep(0.1)
        flush_info(logs, None)
        raise TimeoutError(f"Application frontend was not open after {timeout}s")

    def _get_node_by_service_id(self, node_id):
        return next((node for node in self.nodes if node.node_id == node_id), None)

    def find_primary(self, nodes=None, timeout=10, log_capture=None, **kwargs):
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
                with node.client(**kwargs) as c:
                    try:
                        logs = []
                        res = c.get("/node/network", timeout=1, log_capture=logs)
                        assert res.status_code == http.HTTPStatus.OK.value, res

                        body = res.body.json()
                        view = body["current_view"]
                        primary_id = body["primary_id"]
                        if primary_id is not None:
                            break

                    except Exception:
                        LOG.warning(
                            f"Could not successfully connect to node {node.local_node_id}. Retrying..."
                        )

            if primary_id is not None:
                break
            time.sleep(0.1)

        if primary_id is None:
            flush_info(logs, log_capture, 0)
            raise PrimaryNotFound

        return (self._get_node_by_service_id(primary_id), view)

    def find_backups(self, primary=None, timeout=3, log_capture=None):
        if primary is None:
            primary, _ = self.find_primary(timeout=timeout, log_capture=log_capture)
        return [n for n in self.get_joined_nodes() if n != primary]

    def find_any_backup(self, primary=None, timeout=3, log_capture=None):
        return random.choice(
            self.find_backups(primary=primary, timeout=timeout, log_capture=log_capture)
        )

    def find_node_by_role(self, role=NodeRole.ANY, log_capture=None):
        role_ = (
            random.choice([NodeRole.PRIMARY, NodeRole.BACKUP])
            if NodeRole.ANY == role
            else role
        )
        if role_ == NodeRole.PRIMARY:
            return self.find_primary(log_capture=log_capture)[0]
        else:
            return self.find_any_backup(log_capture=log_capture)

    def find_random_node(self):
        return random.choice(self.get_joined_nodes())

    def find_nodes(self, timeout=3, log_capture=None):
        primary, _ = self.find_primary(timeout=timeout, log_capture=log_capture)
        backups = self.find_backups(
            primary=primary, timeout=timeout, log_capture=log_capture
        )
        return primary, backups

    def find_primary_and_any_backup(self, timeout=3):
        primary, backups = self.find_nodes(timeout)
        backup = random.choice(backups)
        return primary, backup

    def resize(self, target_count, args):
        node_count = len(self.get_joined_nodes())
        initial_node_count = node_count
        LOG.info(f"Resizing network from {initial_node_count} to {target_count} nodes")
        while node_count < target_count:
            new_node = self.create_node("local://localhost")
            self.join_node(new_node, args.package, args)
            self.trust_node(new_node, args)
            node_count += 1
        while node_count > target_count:
            primary, backup = self.find_primary_and_any_backup()
            self.retire_node(primary, backup)
            backup.stop()
            node_count -= 1
        primary, _ = self.find_primary()
        self.wait_for_all_nodes_to_commit(primary)
        LOG.success(
            f"Resized network from {initial_node_count} to {target_count} nodes"
        )
        return initial_node_count

    def wait_for_all_nodes_to_commit(self, primary=None, tx_id=None, timeout=10):
        """
        Wait for all nodes to have joined the network and committed all transactions
        executed on the primary.
        """
        if not (primary or tx_id):
            raise ValueError("Either a valid TxID or primary node should be specified")

        end_time = time.time() + timeout

        # If no TxID is specified, retrieve latest readable one
        if tx_id is None:
            while time.time() < end_time:
                with primary.client() as c:
                    resp = c.get("/node/state")  # Well-known read-only endpoint
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
                        f"/node/tx?transaction_id={tx_id}",
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
                with node.client() as c:
                    r = c.get("/node/consensus")
                    pprint.pprint(r.body.json())
        assert expected == commits, f"Multiple commit values: {commits}"

    def _check_node_status(
        self,
        remote_node,
        node_id,
        node_status,  # None indicates that the node should not be present
        **kwargs,
    ):
        with remote_node.client(**kwargs) as c:
            r = c.get(f"/node/network/nodes/{node_id}")
            resp = r.body.json()
            return (
                r.status_code == http.HTTPStatus.NOT_FOUND.value
                and node_status is None
                and resp["error"]["message"] == "Node not found"
            ) or (
                r.status_code == http.HTTPStatus.OK.value
                and node_status is not None
                and resp["status"] == node_status.value
            )

    def wait_for_node_in_store(
        self, remote_node, node_id, node_status, timeout=3, **kwargs
    ):
        success = False
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                if self._check_node_status(remote_node, node_id, node_status, **kwargs):
                    success = True
                    break
            except TimeoutError:
                pass
            time.sleep(0.5)
        if not success:
            raise TimeoutError(
                f'Node {node_id} is not in expected state: {node_status or "absent"})'
            )

    def wait_for_all_nodes_to_be_trusted(self, remote_node, timeout=3):
        for n in self.nodes:
            self.wait_for_node_in_store(
                remote_node, n.node_id, ccf.ledger.NodeStatus.TRUSTED, timeout
            )

    def wait_for_new_primary(
        self,
        old_primary,
        nodes=None,
        timeout_multiplier=DEFAULT_TIMEOUT_MULTIPLIER,
        **kwargs,
    ):
        # We arbitrarily pick twice the election duration to protect ourselves against the somewhat
        # but not that rare cases when the first round of election fails (short timeout are particularly susceptible to this)
        timeout = self.observed_election_duration * timeout_multiplier
        LOG.info(
            f"Waiting up to {timeout}s for a new primary different from {old_primary.local_node_id} ({old_primary.node_id}) to be elected..."
        )
        start_time = time.time()
        end_time = start_time + timeout
        error = TimeoutError
        logs = []

        while time.time() < end_time:
            try:
                logs = []
                new_primary, new_term = self.find_primary(
                    nodes=nodes, log_capture=logs, **kwargs
                )
                if new_primary.node_id != old_primary.node_id:
                    flush_info(logs, None)
                    delay = time.time() - start_time
                    LOG.info(
                        f"New primary after {delay:.2f}s is {new_primary.local_node_id} ({new_primary.node_id}) in term {new_term}"
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
        self,
        expected_node_ids,
        nodes=None,
        timeout_multiplier=DEFAULT_TIMEOUT_MULTIPLIER,
    ):
        # We arbitrarily pick twice the election duration to protect ourselves against the somewhat
        # but not that rare cases when the first round of election fails (short timeout are particularly susceptible to this)
        timeout = self.observed_election_duration * timeout_multiplier
        LOG.info(
            f"Waiting up to {timeout}s for a new primary in {expected_node_ids} to be elected..."
        )
        start_time = time.time()
        end_time = start_time + timeout
        error = TimeoutError
        logs = []
        while time.time() < end_time:
            try:
                logs = []
                new_primary, new_term = self.find_primary(
                    nodes=nodes, log_capture=logs, timeout=1
                )
                if new_primary.node_id in expected_node_ids:
                    flush_info(logs, None)
                    delay = time.time() - start_time
                    LOG.info(
                        f"New primary after {delay:.2f}s is {new_primary.local_node_id} ({new_primary.node_id}) in term {new_term}"
                    )
                    return (new_primary, new_term)
            except PrimaryNotFound:
                error = PrimaryNotFound
            except Exception:
                pass
            time.sleep(0.1)
        flush_info(logs, None)
        raise error(f"A new primary was not elected after {timeout} seconds")

    def wait_for_primary_unanimity(
        self, nodes=None, timeout_multiplier=DEFAULT_TIMEOUT_MULTIPLIER, min_view=None
    ):
        timeout = self.observed_election_duration * timeout_multiplier
        LOG.info(
            f"Waiting up to {timeout}s for all nodes to agree on the primary in view >= {min_view}"
        )
        start_time = time.time()
        end_time = start_time + timeout

        nodes = nodes or self.get_joined_nodes()
        primaries = {n.node_id: None for n in nodes}
        while time.time() < end_time:
            logs = []
            for node in nodes:
                try:
                    primary, view = self.find_primary(
                        nodes=[node], log_capture=logs, timeout=1
                    )
                    if min_view is None or view > min_view:
                        primaries[node.node_id] = primary
                except PrimaryNotFound:
                    LOG.info(f"Primary not found for {node.node_id}")
                    primaries[node.node_id] = None
            # Stop checking once all primaries are the same
            if all(primaries.values()) and len(set(primaries.values())) == 1:
                break
            time.sleep(0.1)
        flush_info(logs)
        all_good = all(primaries.values()) and len(set(primaries.values())) == 1
        if not all_good:
            for node in nodes:
                with node.client() as c:
                    r = c.get("/node/consensus")
                    pprint.pprint(r.body.json())
        primary_opinions = {n: p.node_id if p else p for n, p in primaries.items()}
        assert all_good, f"Disagreement about primaries: {primary_opinions}"
        delay = time.time() - start_time
        primary = list(primaries.values())[0]
        LOG.info(
            f"Primary unanimity after {delay:.2f}s: {primary.local_node_id} ({primary.node_id})"
        )
        return primary

    def get_committed_snapshots(self, node, target_seqno=None, force_txs=True):
        # Wait for the snapshot including target_seqno to be committed before
        # copying snapshot directory. Do not issue transactions if force_txs is False
        # and expect snapshot to have already been created.
        if target_seqno is None:
            with node.client() as c:
                r = c.get("/node/commit").body.json()
                target_seqno = TxID.from_str(r["transaction_id"]).seqno

        def wait_for_snapshots_to_be_committed(src_dir, list_src_dir_func, timeout=20):
            if not force_txs:
                return True

            LOG.info(
                f"Waiting for a snapshot to be committed including seqno {target_seqno} in {src_dir}"
            )
            end_time = time.time() + timeout
            while True:
                for f in list_src_dir_func(src_dir):
                    snapshot_seqno = infra.node.get_snapshot_seqnos(f)[1]
                    if snapshot_seqno >= target_seqno and infra.node.is_file_committed(
                        f
                    ):
                        LOG.info(
                            f"Found committed snapshot {f} for seqno {target_seqno} after {timeout - (end_time - time.time()):.2f}s"
                        )
                        return True

                if time.time() > end_time:
                    LOG.error(
                        f"Could not find committed snapshot for seqno {target_seqno} after {timeout:.2f}s in {src_dir}: {list_src_dir_func(src_dir)}"
                    )
                    return False

                # Update state digest as a neutral write operation, to advance commit
                member = self.consortium.get_any_active_member()
                for _ in range(self.args.snapshot_tx_interval // 2):
                    r = member.update_ack_state_digest(node)
                with node.client() as c:
                    c.wait_for_commit(r)
                time.sleep(0.1)

        return node.get_committed_snapshots(wait_for_snapshots_to_be_committed)

    def _get_ledger_public_view_at(self, node, call, seqno, timeout):
        end_time = time.time() + timeout
        self.consortium.force_ledger_chunk(node)
        while time.time() < end_time:
            try:
                return call(seqno)
            except Exception as ex:
                LOG.info(f"Exception: {ex}")
                time.sleep(0.1)
        raise TimeoutError(
            f"Could not read transaction at seqno {seqno} from ledger {node.remote.ledger_paths()} after {timeout}s"
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

    @functools.cached_property
    def cert_path(self):
        return os.path.join(self.common_dir, "service_cert.pem")

    @functools.cached_property
    def cert(self):
        with open(self.cert_path, encoding="utf-8") as c:
            service_cert = load_pem_x509_certificate(
                c.read().encode("ascii"), default_backend()
            )
            return service_cert

    def verify_service_certificate_validity_period(self, expected_validity_days):
        primary, _ = self.find_primary()
        if primary.major_version and primary.major_version <= 1:
            # Service certificate validity period is hardcoded in 1.x
            LOG.warning("Skipping service certificate validity check for 1.x service")
            return

        with primary.client() as c:
            r = c.get("/node/network")
            valid_from, valid_to = infra.crypto.get_validity_period_from_pem_cert(
                r.body.json()["service_certificate"]
            )

        if self.service_certificate_valid_from is None:
            # If the service certificate has not been renewed, assume that certificate has
            # been issued within this test run
            expected_valid_from = datetime.now(timezone.utc) - timedelta(hours=1)
            if valid_from < expected_valid_from:
                raise ValueError(
                    f'Service certificate is too old: valid from "{valid_from}" older than expected "{expected_valid_from}"'
                )

        # Note: CCF substracts one second from validity period since x509 specifies
        # that validity dates are inclusive.
        expected_valid_to = valid_from + timedelta(
            days=expected_validity_days, seconds=-1
        )
        if valid_to != expected_valid_to:
            raise ValueError(
                f'Validity period for service certificate is not as expected: valid to "{valid_to}" but expected "{expected_valid_to}"'
            )

        validity_period = valid_to - valid_from + timedelta(seconds=1)
        LOG.info(
            f"Certificate validity period for service: {valid_from} - {valid_to} (for {validity_period})"
        )

    def refresh_service_identity_file(self, args):
        """
        Refresh service_cert.pem from the current primary node, so that future client
        connections pick up the new service certificate.
        """
        primary = self.find_random_node()
        with primary.client() as c:
            r = c.get("/node/network")
            assert r.status_code == 200, r
            new_service_identity = r.body.json()["service_certificate"]
        identity_filepath = os.path.join(self.common_dir, "service_cert.pem")
        with open(identity_filepath, "r", encoding="utf-8") as f:
            before_digest = hashlib.sha256(f.read().encode()).hexdigest()
        LOG.info(f"Before refresh, service_cert.pem was sha256:{before_digest}")
        after_digest = hashlib.sha256(new_service_identity.encode()).hexdigest()
        LOG.info(f"After refresh, service_cert.pem is sha256:{after_digest}")
        with open(identity_filepath, "w", encoding="utf-8") as f:
            f.write(new_service_identity)

    def save_service_identity(self, args):
        n = self.find_random_node()
        with n.client() as c:
            r = c.get("/node/network")
            assert r.status_code == 200, r
            current_ident = r.body.json()["service_certificate"]
        prev_cert_count = 0
        previous_identity = os.path.join(self.common_dir, "previous_service_cert.pem")
        while os.path.exists(previous_identity):
            prev_cert_count += 1
            previous_identity = os.path.join(
                self.common_dir, f"previous_service_cert_{prev_cert_count}.pem"
            )
        with open(previous_identity, "w", encoding="utf-8") as f:
            f.write(current_ident)
        args.previous_service_identity_file = previous_identity
        return current_ident

    def identity(self, name=None):
        if name is not None:
            return infra.clients.Identity(
                os.path.join(self.common_dir, f"{name}_privk.pem"),
                os.path.join(self.common_dir, f"{name}_cert.pem"),
                name,
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
    service_load=None,
    node_data_json_file=None,
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
        service_load=service_load,
        node_data_json_file=node_data_json_file,
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
        net.stop_all_nodes(skip_verification=True, accept_ledger_diff=True)
        if init_partitioner:
            net.partitioner.cleanup()
