# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.proc
import infra.logging_app as app
import infra.utils
import infra.github
import infra.jwt_issuer
import cimetrics.env
import suite.test_requirements as reqs
import ccf.ledger
import os
import json
import time
from e2e_logging import test_random_receipts
from governance import test_all_nodes_cert_renewal


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


def get_new_constitution_for_install(args, install_path):
    constitution_directory = os.path.join(
        install_path,
        "../src/runtime_config/default"
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
    LOG.info("Update constitution")
    primary, _ = network.find_primary()
    new_constitution = get_new_constitution_for_install(args, install_path)
    network.consortium.set_constitution(primary, new_constitution)

    # Note: Changes to constitution between versions should be tested here

    LOG.info(f"Add node to new service [cycle nodes: {cycle_existing_nodes}]")
    nodes_to_cycle = network.get_joined_nodes() if cycle_existing_nodes else []
    nodes_to_add_count = len(nodes_to_cycle) if cycle_existing_nodes else 1

    for _ in range(0, nodes_to_add_count):
        new_node = network.create_node(
            "local://localhost",
            binary_dir=binary_dir,
            library_dir=library_dir,
            version=version,
        )
        network.join_node(new_node, args.package, args)
        network.trust_node(new_node, args)
        new_node.verify_certificate_validity_period(
            expected_validity_period_days=DEFAULT_NODE_CERTIFICATE_VALIDITY_DAYS
        )

    for node in nodes_to_cycle:
        network.retire_node(primary, node)
        if primary == node:
            primary, _ = network.wait_for_new_primary(primary)
        node.stop()

    test_all_nodes_cert_renewal(network, args)

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


def set_js_args(args, from_install_path):
    # Use from_version's app and constitution as new JS features may not be available
    # on older versions, but upgrade to the new constitution once the new network is ready
    js_app_directory = (
        "../samples/apps/logging/js"
        if from_install_path == LOCAL_CHECKOUT_DIRECTORY
        else "samples/logging/js"
    )
    args.js_app_bundle = os.path.join(from_install_path, js_app_directory)

    get_new_constitution_for_install(args, from_install_path)


def run_code_upgrade_from(
    args,
    from_install_path,
    to_install_path,
    from_version=None,
    to_version=None,
):
    from_binary_dir, from_library_dir = get_bin_and_lib_dirs_for_install_path(
        from_install_path
    )
    to_binary_dir, to_library_dir = get_bin_and_lib_dirs_for_install_path(
        to_install_path
    )

    set_js_args(args, from_install_path)

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
            network.start_and_join(args)

            old_nodes = network.get_joined_nodes()
            primary, _ = network.find_primary()

            LOG.info("Apply transactions to old service")
            issue_activity_on_live_service(network, args)

            new_code_id = infra.utils.get_code_id(
                args.enclave_type,
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
                network.trust_node(new_node, args)
                # For 2.x nodes joining a 1.x service before the constitution is update,
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
                args.oe_binary,
                args.package,
                library_dir=from_library_dir,
            )
            primary, _ = network.find_primary()
            network.consortium.retire_code(primary, old_code_id)

            for node in old_nodes:
                network.retire_node(primary, node)
                if primary == node:
                    primary, _ = network.wait_for_new_primary(primary)
                node.stop()

            LOG.info("Service is now made of new nodes only")

            # Rollover JWKS so that new primary must read historical CA bundle table
            # and retrieve new keys via auto refresh
            jwt_issuer.refresh_keys()
            # Note: /gov/jwt_keys/all endpoint was added in 2.x
            primary, _ = network.find_nodes()
            if not primary.major_version or primary.major_version > 1:
                jwt_issuer.wait_for_refresh(network)
            else:
                time.sleep(3)

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
            network.get_latest_ledger_public_state()


@reqs.description("Run live compatibility with latest LTS")
def run_live_compatibility_with_latest(args, repo, local_branch):
    """
    Tests that a service from the latest LTS can be safely upgraded to the version of
    the local checkout.
    """
    lts_version, lts_install_path = repo.install_latest_lts_for_branch(
        os.getenv(ENV_VAR_LATEST_LTS_BRANCH_NAME, local_branch)
    )
    local_major_version = infra.github.get_major_version_from_branch_name(local_branch)
    LOG.info(
        f'From LTS {lts_version} to local "{local_branch}" branch (version: {local_major_version})'
    )
    if not args.dry_run:
        run_code_upgrade_from(
            args,
            from_install_path=lts_install_path,
            to_install_path=LOCAL_CHECKOUT_DIRECTORY,
            from_version=lts_version,
            to_version=local_major_version,
        )
    return lts_version


@reqs.description("Run live compatibility with next LTS")
def run_live_compatibility_with_following(args, repo, local_branch):
    """
    Tests that a service from the local checkout can be safely upgraded to the version of
    the next LTS.
    """
    lts_version, lts_install_path = repo.install_next_lts_for_branch(local_branch)
    if lts_version is None:
        LOG.warning(f"No next LTS for local {local_branch} branch")
        return None

    local_major_version = infra.github.get_major_version_from_branch_name(local_branch)
    LOG.info(
        f'From local "{local_branch}" branch (version: {local_major_version}) to LTS {lts_version}'
    )
    if not args.dry_run:
        run_code_upgrade_from(
            args,
            from_install_path=LOCAL_CHECKOUT_DIRECTORY,
            to_install_path=lts_install_path,
            from_version=local_major_version,
            to_version=lts_version,
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
    lts_releases = repo.get_lts_releases()

    LOG.info(f"LTS releases: {[r[1] for r in lts_releases.items()]}")

    lts_versions = []

    # Add an empty entry to release to indicate local checkout
    # Note: dicts are ordered from Python3.7
    lts_releases[None] = None

    jwt_issuer = infra.jwt_issuer.JwtIssuer(
        "https://localhost", refresh_interval=args.jwt_key_refresh_interval_s
    )
    with jwt_issuer.start_openid_server():
        txs = app.LoggingTxs(jwt_issuer=jwt_issuer)
        for idx, (_, lts_release) in enumerate(lts_releases.items()):
            if lts_release:
                version, install_path = repo.install_release(lts_release)
                lts_versions.append(version)
                set_js_args(args, install_path)
            else:
                version = args.ccf_version
                install_path = LOCAL_CHECKOUT_DIRECTORY

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
                    network.start_and_join(args)
                else:
                    LOG.info(f"Recovering service (new version: {version})")
                    network = infra.network.Network(
                        **network_args, existing_network=network
                    )
                    network.start_in_recovery(
                        args,
                        ledger_dir,
                        committed_ledger_dir,
                        snapshot_dir=snapshot_dir,
                    )
                    network.recover(args)

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

                snapshot_dir = (
                    network.get_committed_snapshots(primary) if use_snapshot else None
                )
                ledger_dir, committed_ledger_dir = primary.get_ledger(
                    include_read_only_dirs=True
                )
                network.stop_all_nodes(skip_verification=True)

                # Check that ledger and snapshots can be parsed
                ccf.ledger.Ledger([committed_ledger_dir]).get_latest_public_state()
                if snapshot_dir:
                    for s in os.listdir(snapshot_dir):
                        with ccf.ledger.Snapshot(
                            os.path.join(snapshot_dir, s)
                        ) as snapshot:
                            snapshot.get_public_domain()

    return lts_versions


if __name__ == "__main__":

    def add(parser):
        parser.add_argument("--check-ledger-compatibility", action="store_true")
        parser.add_argument(
            "--compatibility-report-file", type=str, default="compatibility_report.json"
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

    repo = infra.github.Repository()
    # Cheeky! We reuse cimetrics env as a reliable way to retrieve the
    # current branch on any environment (either local checkout or CI run)
    env = cimetrics.env.get_env()

    if args.dry_run:
        LOG.warning("Dry run: no compatibility check")

    compatibility_report = {}
    compatibility_report["version"] = args.ccf_version
    compatibility_report["live compatibility"] = {}
    latest_lts_version = run_live_compatibility_with_latest(args, repo, env.branch)
    following_lts_version = run_live_compatibility_with_following(
        args, repo, env.branch
    )
    compatibility_report["live compatibility"].update(
        {"with latest": latest_lts_version}
    )
    compatibility_report["live compatibility"].update(
        {"with following": following_lts_version}
    )

    if args.check_ledger_compatibility:
        compatibility_report["data compatibility"] = {}
        lts_versions = run_ledger_compatibility_since_first(
            args, env.branch, use_snapshot=False
        )
        compatibility_report["data compatibility"].update(
            {"with previous ledger": lts_versions}
        )
        lts_versions = run_ledger_compatibility_since_first(
            args, env.branch, use_snapshot=True
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
