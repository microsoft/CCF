# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.proc
import infra.logging_app as app
import infra.utils
import infra.github
import infra.jwt_issuer
import infra.crypto
import infra.node
import suite.test_requirements as reqs
import ccf.ledger
import os
import json
import time
import datetime
import git
from e2e_logging import test_random_receipts
from governance import test_all_nodes_cert_renewal, test_service_cert_renewal
from infra.is_snp import IS_SNP
from reconfiguration import test_migration_2tx_reconfiguration


from loguru import logger as LOG

# Assumption:
# By default, this assumes that the local checkout is not a non-release branch (e.g. main)
# that is older than the latest release branch. This is to simplify the test, and assume
# that the latest release to test compatibility with is the latest available one.
# Use the CCF_LATEST_RELEASE_BRANCH_SUFFIX envvar below if this isn't the case.
ENV_VAR_LATEST_LTS_BRANCH_NAME = (
    "CCF_LATEST_RELEASE_BRANCH_SUFFIX"  # e.g. "release/1.x"
)

LOCAL_CHECKOUT_DIRECTORY = "."

# When a 2.x node joins a 1.x service, the node has to self-endorse
# its certificate, using a default value for the validity period
# hardcoded in CCF.
DEFAULT_NODE_CERTIFICATE_VALIDITY_DAYS = 365


def issue_activity_on_live_service(network, args):
    log_capture = []
    network.txs.issue(
        network, number_txs=args.snapshot_tx_interval * 2, log_capture=log_capture
    )

    # At least one transaction that will require historical fetching
    network.txs.issue(network, number_txs=1, repeat=True)

    # At least one transaction that will require forwarding
    network.txs.issue(network, number_txs=1, on_backup=True)


def get_new_constitution_for_install(args, install_path):
    constitution_directory = os.path.join(
        install_path,
        "../samples/constitutions/default"
        if install_path == LOCAL_CHECKOUT_DIRECTORY
        else "bin",
    )

    def replace_constitution_fragment(args, fragment_name):
        args.constitution[:] = [
            os.path.join(constitution_directory, fragment_name)
            if fragment_name in f
            else f
            for f in args.constitution
        ]

    # Note: Use resolve.js script from local checkout as only the trivial sandbox
    # version is included in installation
    replace_constitution_fragment(args, "actions.js")
    replace_constitution_fragment(args, "apply.js")
    replace_constitution_fragment(args, "validate.js")

    return args.constitution


def test_new_service(
    network,
    args,
    install_path,
    binary_dir,
    library_dir,
    version,
    cycle_existing_nodes=False,
):
    if IS_SNP:
        LOG.info(
            "Skipping backwards compatibility test for AMD nodes until either we patch 2.x or we confirm that we don't need to do a live upgrade"
        )
        return

    LOG.info("Update constitution")
    primary, _ = network.find_primary()
    new_constitution = get_new_constitution_for_install(args, install_path)
    network.consortium.set_constitution(primary, new_constitution)

    all_nodes = network.get_joined_nodes()

    # Note: Changes to constitution between versions should be tested here

    LOG.info(f"Add node to new service [cycle nodes: {cycle_existing_nodes}]")
    nodes_to_cycle = network.get_joined_nodes() if cycle_existing_nodes else []
    nodes_to_add_count = len(nodes_to_cycle) if cycle_existing_nodes else 1

    # Pre-2.0 nodes require X509 time format
    valid_from = str(infra.crypto.datetime_to_X509time(datetime.datetime.utcnow()))

    for _ in range(0, nodes_to_add_count):
        new_node = network.create_node(
            "local://localhost",
            binary_dir=binary_dir,
            library_dir=library_dir,
            version=version,
        )
        network.join_node(new_node, args.package, args)
        network.trust_node(
            new_node,
            args,
            valid_from=valid_from,
        )
        new_node.verify_certificate_validity_period(
            expected_validity_period_days=DEFAULT_NODE_CERTIFICATE_VALIDITY_DAYS
        )
        all_nodes.append(new_node)

    for node in nodes_to_cycle:
        network.retire_node(primary, node)
        if primary == node:
            primary, _ = network.wait_for_new_primary(primary)
            # Stopping a node immediately after its removal being
            # committed and an election is not safe: the successor
            # primary may need to re-establish commit on a config
            # that includes the retire node.
            # See https://github.com/microsoft/CCF/issues/1713
            # for more detail. Until the dedicated endpoint exposing
            # this safely is implemented, we work around this by
            # submitting and waiting for commit on another transaction.
            network.txs.issue(network, number_txs=1, repeat=True)
        node.stop()

    test_all_nodes_cert_renewal(network, args, valid_from=valid_from)
    test_service_cert_renewal(network, args, valid_from=valid_from)

    if args.check_2tx_reconfig_migration:
        test_migration_2tx_reconfiguration(
            network,
            args,
            initial_is_1tx=False,  # Reconfiguration type added in 2.x
            binary_dir=binary_dir,
            library_dir=library_dir,
            version=version,
            valid_from=valid_from,
        )

    LOG.info("Apply transactions to new nodes only")
    issue_activity_on_live_service(network, args)
    test_random_receipts(network, args, lts=True)


# Local build and install bin/ and lib/ directories differ
def get_bin_and_lib_dirs_for_install_path(install_path):
    return (
        [LOCAL_CHECKOUT_DIRECTORY] * 2
        if install_path == LOCAL_CHECKOUT_DIRECTORY
        else (os.path.join(install_path, "bin"), os.path.join(install_path, "lib"))
    )


def set_js_args(args, from_install_path, to_install_path=None):
    # Use from_version's app and constitution as new JS features may not be available
    # on older versions, but upgrade to the new constitution once the new network is ready
    js_app_directory = (
        "../samples/apps/logging/js"
        if from_install_path == LOCAL_CHECKOUT_DIRECTORY
        else "samples/logging/js"
    )
    args.js_app_bundle = os.path.join(from_install_path, js_app_directory)
    if to_install_path:
        args.new_js_app_bundle = os.path.join(
            to_install_path, "../samples/apps/logging/js"
        )

    get_new_constitution_for_install(args, from_install_path)


def run_code_upgrade_from(
    args,
    from_install_path,
    to_install_path,
    from_version=None,
    to_version=None,
    from_container_image=None,
):
    if IS_SNP:
        LOG.info(
            "Skipping backwards compatibility test for AMD nodes until either we patch 2.x or we confirm that we don't need to do a live upgrade"
        )
        return

    from_binary_dir, from_library_dir = get_bin_and_lib_dirs_for_install_path(
        from_install_path
    )
    to_binary_dir, to_library_dir = get_bin_and_lib_dirs_for_install_path(
        to_install_path
    )

    set_js_args(args, from_install_path, to_install_path)

    jwt_issuer = infra.jwt_issuer.JwtIssuer(
        "https://localhost", refresh_interval=args.jwt_key_refresh_interval_s
    )
    with jwt_issuer.start_openid_server():
        txs = app.LoggingTxs(jwt_issuer=jwt_issuer)
        with infra.network.network(
            args.nodes,
            binary_directory=from_binary_dir,
            library_directory=from_library_dir,
            pdb=args.pdb,
            txs=txs,
            jwt_issuer=jwt_issuer,
            version=from_version,
        ) as network:
            network.start_and_open(args, node_container_image=from_container_image)

            old_nodes = network.get_joined_nodes()
            primary, _ = network.find_primary()
            from_major_version = primary.major_version

            LOG.info("Apply transactions to old service")
            issue_activity_on_live_service(network, args)

            new_code_id = infra.utils.get_code_id(
                args.enclave_type,
                args.enclave_platform,
                args.oe_binary,
                args.package,
                library_dir=to_library_dir,
            )
            network.consortium.add_new_code(primary, new_code_id)

            # Note: alternate between joining from snapshot and replaying entire ledger
            new_nodes = []
            from_snapshot = True
            for _ in range(0, len(old_nodes)):
                new_node = network.create_node(
                    "local://localhost",
                    binary_dir=to_binary_dir,
                    library_dir=to_library_dir,
                    version=to_version,
                )
                network.join_node(
                    new_node, args.package, args, from_snapshot=from_snapshot
                )
                network.trust_node(
                    new_node,
                    args,
                    valid_from=str(  # Pre-2.0 nodes require X509 time format
                        infra.crypto.datetime_to_X509time(datetime.datetime.utcnow())
                    ),
                )
                # For 2.x nodes joining a 1.x service before the constitution is updated,
                # the node certificate validity period is set by the joining node itself
                # as [node startup time, node startup time + 365 days]
                new_node.verify_certificate_validity_period(
                    expected_validity_period_days=DEFAULT_NODE_CERTIFICATE_VALIDITY_DAYS,
                    ignore_proposal_valid_from=True,
                )
                from_snapshot = not from_snapshot
                new_nodes.append(new_node)

            # Verify that all nodes run the expected CCF version
            for node in network.get_joined_nodes():
                # Note: /node/version endpoint was added in 2.x
                if not node.major_version or node.major_version > 1:
                    with node.client() as c:
                        r = c.get("/node/version")
                        expected_version = node.version or args.ccf_version
                        version = r.body.json()["ccf_version"]
                        assert (
                            version == expected_version
                        ), f"For node {node.local_node_id}, expect version {expected_version}, got {version}"

            LOG.info("Apply transactions to hybrid network, with primary as old node")
            issue_activity_on_live_service(network, args)

            old_code_id = infra.utils.get_code_id(
                args.enclave_type,
                args.enclave_platform,
                args.oe_binary,
                args.package,
                library_dir=from_library_dir,
            )
            primary, _ = network.find_primary()
            network.consortium.retire_code(primary, old_code_id)

            for index, node in enumerate(old_nodes):
                network.retire_node(primary, node)
                if primary == node:
                    primary, _ = network.wait_for_new_primary(primary)
                    # Submit tx and wait for commit after node retirement. See
                    # https://github.com/microsoft/CCF/issues/1713 for more detail.
                    network.txs.issue(network, number_txs=1, repeat=True)
                    # This block is here to test the transition period from a network that
                    # does not support custom claims to one that does. It can be removed after
                    # the transition is complete.
                    #
                    # The new build, being unreleased, doesn't have a version at all
                    if not primary.major_version:
                        LOG.info("Upgrade to new JS app")
                        # Upgrade to a version of the app containing an endpoint that
                        # registers custom claims
                        network.consortium.set_js_app_from_dir(
                            primary, args.new_js_app_bundle
                        )
                        LOG.info("Run transaction with additional claim")
                        # With wait_for_sync, the client checks that all nodes, including
                        # the minority of old ones, have acked the transaction
                        msg_idx = network.txs.idx + 1
                        txid = network.txs.issue(
                            network, number_txs=1, record_claim=True, wait_for_sync=True
                        )
                        assert len(network.txs.pub[msg_idx]) == 1
                        claims = network.txs.pub[msg_idx][-1]["msg"]

                        LOG.info(
                            "Check receipts are fine, including transaction with claims"
                        )
                        test_random_receipts(
                            network,
                            args,
                            lts=True,
                            additional_seqnos={txid.seqno: claims.encode()},
                        )
                        # Also check receipts on an old node
                        if index + 1 < len(old_nodes):
                            next_node = old_nodes[index + 1]
                            test_random_receipts(
                                network,
                                args,
                                lts=True,
                                additional_seqnos={txid.seqno: None},
                                node=next_node,
                            )
                node.stop()

            LOG.info("Service is now made of new nodes only")
            primary, _ = network.find_nodes()

            # Rollover JWKS so that new primary must read historical CA bundle table
            # and retrieve new keys via auto refresh
            if not os.getenv("CONTAINER_NODES"):
                jwt_issuer.refresh_keys()
                # Note: /gov/jwt_keys/all endpoint was added in 2.x
                if not primary.major_version or primary.major_version > 1:
                    jwt_issuer.wait_for_refresh(network)
                else:
                    time.sleep(3)
            else:
                # https://github.com/microsoft/CCF/issues/2608#issuecomment-924785744
                LOG.warning("Skipping JWT refresh as running nodes in container")

            # Code update from 1.x to 2.x requires cycling the freshly-added 2.x nodes
            # once. This is because 2.x nodes will not have an endorsed certificate
            # recorded in the store and thus will not be able to have their certificate
            # refreshed, etc.
            test_new_service(
                network,
                args,
                to_install_path,
                to_binary_dir,
                to_library_dir,
                to_version,
                cycle_existing_nodes=True,
            )

            # Check that the ledger can be parsed
            # Note: When upgrading from 1.x to 2.x, it is possible that ledger chunk are not
            # in sync between nodes, which may cause some chunks to differ when starting
            # from a snapshot. See https://github.com/microsoft/ccf/issues/3613. In such case,
            # we only verify that the ledger can be parsed, even if some chunks are duplicated.
            # This can go once 2.0 is released.
            insecure_ledger_verification = (
                from_major_version == 1 and primary.version_after("ccf-2.0.0-rc7")
            )
            network.get_latest_ledger_public_state(
                insecure=insecure_ledger_verification
            )


@reqs.description("Run live compatibility with latest LTS")
def run_live_compatibility_with_latest(
    args,
    repo,
    local_branch,
    this_release_branch_only=False,
    lts_install_path=None,
    lts_container_image=None,
):
    """
    Tests that a service from the latest LTS can be safely upgraded to the version of
    the local checkout.
    """
    if lts_install_path is None:
        lts_version, lts_install_path = repo.install_latest_lts_for_branch(
            os.getenv(ENV_VAR_LATEST_LTS_BRANCH_NAME, local_branch),
            this_release_branch_only,
            platform=args.enclave_platform,
        )
    else:
        lts_version = infra.github.get_version_from_install(lts_install_path)

    if lts_version is None:
        LOG.warning(
            f"Latest LTS not found for {local_branch} branch (this_release_branch_only: {this_release_branch_only})"
        )
        return None

    LOG.info(f"From LTS {lts_version} to local {local_branch} branch")
    if not args.dry_run:
        run_code_upgrade_from(
            args,
            from_install_path=lts_install_path,
            to_install_path=LOCAL_CHECKOUT_DIRECTORY,
            from_version=lts_version,
            to_version=None,
            from_container_image=lts_container_image,
        )
    return lts_version


@reqs.description("Run ledger compatibility since first LTS")
def run_ledger_compatibility_since_first(args, local_branch, use_snapshot):
    """
    Tests that a service from the very first LTS can be recovered
    to the next LTS, and so forth, until the version of the local checkout.

    The recovery process uses snapshot is `use_snapshot` is True. Otherwise, the
    entire historical ledger is used.
    """

    LOG.info("Use snapshot: {}", use_snapshot)
    repo = infra.github.Repository()
    lts_releases = repo.get_lts_releases(local_branch)
    has_pre_2_rc7_ledger = False

    LOG.info(f"LTS releases: {[r[1] for r in lts_releases.items()]}")

    lts_versions = []

    # Add an empty entry to release to indicate local checkout
    # Note: dicts are ordered from Python3.7
    lts_releases[None] = None

    jwt_issuer = infra.jwt_issuer.JwtIssuer(
        "https://localhost", refresh_interval=args.jwt_key_refresh_interval_s
    )
    previous_version = None
    with jwt_issuer.start_openid_server():
        txs = app.LoggingTxs(jwt_issuer=jwt_issuer)
        for idx, (_, lts_release) in enumerate(lts_releases.items()):
            if lts_release:
                version, install_path = repo.install_release(
                    lts_release,
                    platform=args.enclave_platform,
                )
                lts_versions.append(version)
                set_js_args(args, install_path)
            else:
                version = args.ccf_version
                install_path = LOCAL_CHECKOUT_DIRECTORY
                get_new_constitution_for_install(args, install_path)

            binary_dir, library_dir = get_bin_and_lib_dirs_for_install_path(
                install_path
            )

            if not args.dry_run:
                network_args = {
                    "hosts": args.nodes,
                    "binary_dir": binary_dir,
                    "library_dir": library_dir,
                    "txs": txs,
                    "jwt_issuer": jwt_issuer,
                    "version": version,
                }
                if idx == 0:
                    LOG.info(f"Starting new service (version: {version})")
                    network = infra.network.Network(**network_args)
                    network.start_and_open(args)
                else:
                    LOG.info(f"Recovering service (new version: {version})")
                    network = infra.network.Network(
                        **network_args, existing_network=network
                    )
                    network.start_in_recovery(
                        args,
                        ledger_dir,
                        committed_ledger_dirs,
                        snapshots_dir=snapshots_dir,
                    )
                    # Recovery count is not stored in pre-2.0.3 ledgers
                    network.recover(
                        args,
                        expected_recovery_count=1
                        if not infra.node.version_after(previous_version, "ccf-2.0.3")
                        else None,
                    )

                previous_version = version

                nodes = network.get_joined_nodes()
                primary, _ = network.find_primary()

                # Verify that all nodes run the expected CCF version
                for node in nodes:
                    # Note: /node/version endpoint and custom certificate validity
                    # were added in 2.x
                    if not node.major_version or node.major_version > 1:
                        with node.client() as c:
                            r = c.get("/node/version")
                            expected_version = node.version or args.ccf_version
                            version = r.body.json()["ccf_version"]
                            assert (
                                r.body.json()["ccf_version"] == expected_version
                            ), f"Node version is not {expected_version}"
                        node.verify_certificate_validity_period()

                # Rollover JWKS so that new primary must read historical CA bundle table
                # and retrieve new keys via auto refresh
                jwt_issuer.refresh_keys()
                # Note: /gov/jwt_keys/all endpoint was added in 2.x
                primary, _ = network.find_nodes()
                if not primary.major_version or primary.major_version > 1:
                    jwt_issuer.wait_for_refresh(network)
                else:
                    time.sleep(3)

                if idx > 0:
                    test_new_service(
                        network,
                        args,
                        install_path,
                        binary_dir,
                        library_dir,
                        version,
                    )

                # We accept ledger chunk file differences during upgrades
                # from 1.x to 2.x post rc7 ledger. This is necessary because
                # the ledger files may not be chunked at the same interval
                # between those versions (see https://github.com/microsoft/ccf/issues/3613;
                # 1.x ledgers do not contain the header flags to synchronize ledger chunks).
                # This can go once 2.0 is released.
                current_version_past_2_rc7 = primary.version_after("ccf-2.0.0-rc7")
                has_pre_2_rc7_ledger = (
                    not current_version_past_2_rc7 or has_pre_2_rc7_ledger
                )
                is_ledger_chunk_breaking = (
                    has_pre_2_rc7_ledger and current_version_past_2_rc7
                )

                snapshots_dir = (
                    network.get_committed_snapshots(primary) if use_snapshot else None
                )

                network.save_service_identity(args)
                network.stop_all_nodes(
                    skip_verification=True,
                    accept_ledger_diff=is_ledger_chunk_breaking,
                )
                ledger_dir, committed_ledger_dirs = primary.get_ledger()

                # Check that ledger and snapshots can be parsed
                ccf.ledger.Ledger(committed_ledger_dirs).get_latest_public_state()
                if snapshots_dir:
                    for s in os.listdir(snapshots_dir):
                        with ccf.ledger.Snapshot(
                            os.path.join(snapshots_dir, s)
                        ) as snapshot:
                            snapshot.get_public_domain()

    return lts_versions


if __name__ == "__main__":

    def add(parser):
        parser.add_argument("--check-ledger-compatibility", action="store_true")
        parser.add_argument("--check-2tx-reconfig-migration", action="store_true")
        parser.add_argument(
            "--compatibility-report-file", type=str, default="compatibility_report.json"
        )
        # It is only possible to test compatibility with past releases since only the local infra
        # is able to spawn old nodes
        parser.add_argument(
            "--release-install-path",
            type=str,
            help='Absolute path to existing CCF release, e.g. "/opt/ccf"',
            default=None,
        )
        parser.add_argument(
            "--release-install-image",
            type=str,
            help="If --release-install-path is set, specify a docker image to run release in (only if CONTAINER_NODES envvar is set) ",
            default=None,
        )
        parser.add_argument("--dry-run", action="store_true")

    args = infra.e2e_args.cli_args(add)

    # JS generic is the only app included in CCF install
    args.package = "libjs_generic"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.jwt_key_refresh_interval_s = 3
    args.sig_ms_interval = 1000  # Set to cchost default value

    # Hardcoded because host only accepts info log on release builds
    args.host_log_level = "info"

    # For compatibility with <= 2.x versions as enclave platform
    # was introduced in 3.x
    if args.enclave_platform == "virtual":
        args.enclave_type = "virtual"

    repo = infra.github.Repository()
    local_branch = (
        infra.github.GitEnv.local_branch()
        or git.Repo(os.path.dirname(__file__), search_parent_directories=True).active_branch
    )

    if args.dry_run:
        LOG.warning("Dry run: no compatibility check")

    compatibility_report = {}
    compatibility_report["version"] = args.ccf_version
    compatibility_report["live compatibility"] = {}
    if args.release_install_path:
        version = run_live_compatibility_with_latest(
            args,
            repo,
            local_branch,
            lts_install_path=args.release_install_path,
            lts_container_image=args.release_install_image,
        )
        compatibility_report["live compatibility"].update(
            {f"with release ({args.release_install_path})": version}
        )
    else:

        # Compatibility with previous LTS
        # (e.g. when releasing 2.0.1, check compatibility with existing 1.0.17)
        latest_lts_version = run_live_compatibility_with_latest(
            args, repo, local_branch, this_release_branch_only=False
        )
        compatibility_report["live compatibility"].update(
            {"with previous LTS": latest_lts_version}
        )

        # Compatibility with latest LTS on the same release branch
        # (e.g. when releasing 2.0.1, check compatibility with existing 2.0.0)
        latest_lts_version = run_live_compatibility_with_latest(
            args, repo, local_branch, this_release_branch_only=True
        )
        compatibility_report["live compatibility"].update(
            {"with same LTS": latest_lts_version}
        )

        if args.check_ledger_compatibility:
            compatibility_report["data compatibility"] = {}
            lts_versions = run_ledger_compatibility_since_first(
                args, local_branch, use_snapshot=False
            )
            compatibility_report["data compatibility"].update(
                {"with previous ledger": lts_versions}
            )
            lts_versions = run_ledger_compatibility_since_first(
                args, local_branch, use_snapshot=True
            )
            compatibility_report["data compatibility"].update(
                {"with previous snapshots": lts_versions}
            )

    if not args.dry_run:
        with open(args.compatibility_report_file, "w", encoding="utf-8") as f:
            json.dump(compatibility_report, f, indent=2)
            LOG.info(
                f"Compatibility report written to {args.compatibility_report_file}"
            )

    LOG.success(f"Compatibility report:\n {json.dumps(compatibility_report, indent=2)}")
