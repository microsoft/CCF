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

# pylint: disable=import-error, no-name-in-module
from setuptools.extern.packaging.version import Version  # type: ignore

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


def issue_activity_on_live_service(network, args):
    log_capture = []
    network.txs.issue(
        network, number_txs=args.snapshot_tx_interval * 2, log_capture=log_capture
    )
    # At least one transaction that will require historical fetching
    network.txs.issue(network, number_txs=1, repeat=True, log_capture=log_capture)


# Local build and install bin/ and lib/ directories differ
def get_bin_and_lib_dirs_for_install_path(install_path):
    return (
        [LOCAL_CHECKOUT_DIRECTORY] * 2
        if install_path == LOCAL_CHECKOUT_DIRECTORY
        else (os.path.join(install_path, "bin"), os.path.join(install_path, "lib"))
    )


def run_code_upgrade_from(
    args,
    from_install_path,
    to_install_path,
    from_major_version=None,
    to_major_version=None,
):
    from_binary_dir, from_library_dir = get_bin_and_lib_dirs_for_install_path(
        from_install_path
    )
    to_binary_dir, to_library_dir = get_bin_and_lib_dirs_for_install_path(
        to_install_path
    )

    js_app_directory = (
        "../samples/apps/logging/js"
        if from_install_path == LOCAL_CHECKOUT_DIRECTORY
        else "samples/logging/js"
    )

    args.js_app_bundle = os.path.join(from_install_path, js_app_directory)

    jwt_issuer = infra.jwt_issuer.JwtIssuer("https://localhost")
    with jwt_issuer.start_openid_server():
        txs = app.LoggingTxs(jwt_issuer=jwt_issuer)
        with infra.network.network(
            args.nodes,
            binary_directory=from_binary_dir,
            library_directory=from_library_dir,
            pdb=args.pdb,
            txs=txs,
            jwt_issuer=jwt_issuer,
            version=from_major_version,
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

            # Add one more node than the current count so that at least one new
            # node is required to reach consensus
            # Note: alternate between joining from snapshot and replaying entire ledger
            new_nodes = []
            from_snapshot = True
            for _ in range(0, len(network.get_joined_nodes()) + 1):
                new_node = network.create_node(
                    "local://localhost",
                    binary_dir=to_binary_dir,
                    library_dir=to_library_dir,
                    version=to_major_version,
                )
                network.join_node(
                    new_node, args.package, args, from_snapshot=from_snapshot
                )
                network.trust_node(new_node, args)
                from_snapshot = not from_snapshot
                new_nodes.append(new_node)

            # Verify that all nodes run the expected CCF version
            for node in network.get_joined_nodes():
                # Note: /node/version endpoint was added in 2.x
                if not node.version or node.version > 1:
                    with node.client() as c:
                        r = c.get("/node/version")
                        expected_version = node.version or args.ccf_version
                        version = r.body.json()["ccf_version"]
                        assert (
                            version == expected_version
                        ), f"For node {node.local_node_id}, expect version {expected_version}, got {version}"

            LOG.info("Apply transactions to hybrid network, with primary as old node")
            issue_activity_on_live_service(network, args)

            # Test that new nodes can become primary with old nodes as backups
            # Note: Force a new node as primary by isolating old nodes
            primary, _ = network.find_primary()
            for node in old_nodes:
                node.suspend()

            new_primary, _ = network.wait_for_new_primary(primary, nodes=new_nodes)
            assert (
                new_primary in new_nodes
            ), "New node should have been elected as new primary"

            for node in old_nodes:
                node.resume()

            # Retire one new node, so that at least one old node is required to reach consensus
            other_new_nodes = [node for node in new_nodes if (node is not new_primary)]
            network.retire_node(new_primary, other_new_nodes[0])

            # Rollover JWKS so that new primary must read historical CA bundle table
            # and retrieve new keys via auto refresh
            jwt_issuer.refresh_keys()
            jwt_issuer.wait_for_refresh(network)

            LOG.info("Apply transactions to hybrid network, with primary as new node")
            issue_activity_on_live_service(network, args)

            # Finally, retire old nodes and code id
            old_code_id = infra.utils.get_code_id(
                args.enclave_type,
                args.oe_binary,
                args.package,
                library_dir=from_library_dir,
            )
            network.consortium.retire_code(primary, old_code_id)
            for node in old_nodes:
                network.retire_node(new_primary, node)
                node.stop()

            LOG.info("Apply transactions to new nodes only")
            issue_activity_on_live_service(network, args)

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
    local_major_version = 1
    LOG.info(
        f'From LTS {lts_version} to local "{local_branch}" branch (version: {local_major_version})'
    )
    if not args.dry_run:
        run_code_upgrade_from(
            args,
            from_install_path=lts_install_path,
            to_install_path=LOCAL_CHECKOUT_DIRECTORY,
            from_major_version=Version(lts_version).release[0],
            to_major_version=local_major_version,
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

    local_major_version = 1
    LOG.info(
        f'From local "{local_branch}" branch (version: {local_major_version}) to LTS {lts_version}'
    )
    if not args.dry_run:
        run_code_upgrade_from(
            args,
            from_install_path=LOCAL_CHECKOUT_DIRECTORY,
            to_install_path=lts_install_path,
            from_major_version=local_major_version,
            to_major_version=Version(lts_version).release[0],
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

    LOG.info(f"LTS releases: {[r[1].name for r in lts_releases.items()]}")

    lts_versions = []

    # Add an empty entry to release to indicate local checkout
    # Note: dicts are ordered from Python3.7
    lts_releases[None] = None

    jwt_issuer = infra.jwt_issuer.JwtIssuer("https://localhost")
    with jwt_issuer.start_openid_server():
        txs = app.LoggingTxs(jwt_issuer=jwt_issuer)
        for idx, (_, lts_release) in enumerate(lts_releases.items()):
            if lts_release:
                version, lts_install_path = repo.install_release(lts_release)
                lts_versions.append(version)
                binary_dir, library_dir = get_bin_and_lib_dirs_for_install_path(
                    lts_install_path
                )
                major_version = Version(version).release[0]
                args.js_app_bundle = os.path.join(
                    lts_install_path, "samples/logging/js"
                )
            else:
                version = args.ccf_version
                binary_dir = LOCAL_CHECKOUT_DIRECTORY
                library_dir = LOCAL_CHECKOUT_DIRECTORY
                major_version = infra.github.get_major_version_from_branch_name(
                    local_branch
                )

            if not args.dry_run:
                network_args = {
                    "hosts": args.nodes,
                    "binary_dir": binary_dir,
                    "library_dir": library_dir,
                    "txs": txs,
                    "jwt_issuer": jwt_issuer,
                    "version": major_version,
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
                    # Note: /node/version endpoint was added in 2.x
                    if not node.version or node.version > 1:
                        with node.client() as c:
                            r = c.get("/node/version")
                            expected_version = node.version or args.ccf_version
                            version = r.body.json()["ccf_version"]
                            assert (
                                r.body.json()["ccf_version"] == expected_version
                            ), f"Node version is not {expected_version}"

                # Rollover JWKS so that new primary must read historical CA bundle table
                # and retrieve new keys via auto refresh
                jwt_issuer.refresh_keys()
                jwt_issuer.wait_for_refresh(network)

                issue_activity_on_live_service(network, args)

                snapshot_dir = (
                    network.get_committed_snapshots(primary) if use_snapshot else None
                )
                ledger_dir, committed_ledger_dir = primary.get_ledger(
                    include_read_only_dirs=True
                )
                network.stop_all_nodes(verbose_verification=False)

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
    args.jwt_key_refresh_interval_s = 1

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
        with open(args.compatibility_report_file, "w") as f:
            json.dump(compatibility_report, f, indent=2)
            LOG.info(
                f"Compatibility report written to {args.compatibility_report_file}"
            )

    LOG.success(f"Compatibility report:\n {json.dumps(compatibility_report, indent=2)}")
