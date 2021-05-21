# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.proc
import infra.logging_app as app
import infra.utils
import infra.gh_helper
import infra.jwt
import cimetrics.env
import suite.test_requirements as reqs
import ccf.ledger
import os
import json
from setuptools.extern.packaging.version import Version  # type: ignore


from loguru import logger as LOG

LOCAL_CHECKOUT_DIRECTORY = "."


def issue_activity_on_live_service(network, args):
    log_capture = []
    network.txs.issue(
        network, number_txs=args.snapshot_tx_interval * 2, log_capture=log_capture
    )
    # At least one transaction that will require historical fetching
    network.txs.issue(network, number_txs=1, repeat=True, log_capture=log_capture)


# TODO: Output cmake builds to bin/ and lib/
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

    jwt_issuer = infra.jwt.JwtIssuer("https://localhost")
    with jwt_issuer.start_openid_server() as jwt_server:
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

            # Old nodes only
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
                network.join_node(new_node, args.package, args)
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
                        assert version == (
                            expected_version
                        ), f"For node {node.local_node_id}, expect version {expected_version}, got {version}"

            # Hybrid network, primary is old node
            issue_activity_on_live_service(network, args)

            # Test that new nodes can become primary with old nodes as backups
            # Note: Force a new node as primary by isolating old nodes
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
            jwt_server.stop()
            jwt_issuer.refresh_keys()
            jwt_issuer.restart_openid_server(jwt_server)
            jwt_issuer.wait_for_refresh(network)

            # Hybrid network, primary is new
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

            # New nodes only
            issue_activity_on_live_service(network, args)


# Assumptions:
# 1. No commit on `main` (or any non-release branch) that's older than the latest release branch.


@reqs.description("Run live compatibility with latest LTS")
def run_live_compatibility_with_previous(args, repo, env):
    """
    Tests that a service from the latest LTS can be safely upgraded to the version of
    the local checkout.
    """

    repo = infra.gh_helper.Repository()
    env = cimetrics.env.get_env()
    lts_version, lts_install_path = repo.install_latest_lts_for_branch(env.branch)
    LOG.info(
        f"Running live compatibility test LTS from {lts_version} to local {env.branch} branch"
    )

    run_code_upgrade_from(
        args,
        from_install_path=lts_install_path,
        to_install_path=LOCAL_CHECKOUT_DIRECTORY,
        from_major_version=Version(lts_version).release[0],
        to_major_version=None,
    )

    return lts_version


@reqs.description("Run live compatibility with next LTS")
def run_live_compatibility_with_next(args, repo, env):
    """
    Tests that a service from the latest LTS can be safely upgraded to the version of
    the local checkout.
    """

    lts_version, lts_install_path = repo.install_next_lts_for_branch("release/0.x")
    LOG.info(
        f"Running live compatibility test LTS from {lts_version} to local {env.branch} branch"
    )

    run_code_upgrade_from(
        args,
        from_install_path=LOCAL_CHECKOUT_DIRECTORY,
        to_install_path=lts_install_path,
        from_major_version=None,
        to_major_version=Version(lts_version).release[0],
    )

    return lts_version


def run_ledger_compatibility_since_first(args, use_snapshot):
    """
    Tests that a service from the very first LTS can be recovered
    to the next LTS, and so forth, until the version of the local checkout.

    The recovery process uses snapshot is `use_snapshot` is True. Otherwise, the
    entire historical ledger is used.
    """
    repo = infra.gh_helper.Repository()
    lts_releases = repo.get_lts_releases()

    # TODO: Remove fakeness
    lts_releases_fake = {}
    lts_releases_fake["1.0"] = lts_releases["release/1.x"]
    lts_releases_fake["2.0"] = lts_releases["release/1.x"]

    # Add an empty entry to release to indicate local checkout
    # Note: dicts are ordered from Python3.7
    lts_releases_fake[None] = None

    txs = app.LoggingTxs()
    for idx, (_, lts_release) in enumerate(lts_releases_fake.items()):

        if lts_release:
            version, lts_install_path = repo.install_release(lts_release)
            # TODO: Fix
            # version = "1.0.0"
            # lts_install_path = "/data/git/CCF/build/ccf_install_1.0.0/opt/ccf"
            binary_dir = os.path.join(lts_install_path, "bin")
            library_dir = os.path.join(lts_install_path, "lib")
            major_version = Version(version).release[0]
            # Explictly test the logging app as it was packaged in the very first LTS
            # TODO: Is this the right approach?
            args.js_app_bundle = os.path.join(lts_install_path, "samples/logging/js")
        else:
            version = args.ccf_version
            binary_dir = LOCAL_CHECKOUT_DIRECTORY
            library_dir = LOCAL_CHECKOUT_DIRECTORY
            major_version = None

        network_args = {
            "hosts": args.nodes,
            "binary_dir": binary_dir,
            "library_dir": library_dir,
            "txs": txs,
            "version": major_version,
        }
        if idx == 0:
            LOG.info(f"Starting new service (version: {version})")
            network = infra.network.Network(**network_args)
            network.start_and_join(args)
        else:
            LOG.info(f"Recovering service (new version: {version})")
            network = infra.network.Network(**network_args, existing_network=network)
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
        if not major_version or major_version > 1:
            for node in nodes:
                with node.client() as c:
                    r = c.get("/node/version")
                    assert (
                        r.body.json()["ccf_version"] == version
                    ), f"Node version is not {version}"

        issue_activity_on_live_service(network, args)

        snapshot_dir = (
            network.get_committed_snapshots(primary) if use_snapshot else None
        )

        network.stop_all_nodes(verbose_verification=False)
        ledger_dir, committed_ledger_dir = primary.get_ledger(
            include_read_only_dirs=True
        )

        # Check that the ledger can be parsed on all nodes
        for node in nodes:
            ccf.ledger.Ledger(node.remote.ledger_paths()).get_latest_public_state()


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--compatibility-report-file",
            type=str,
            default=None,
        )

    args = infra.e2e_args.cli_args(add)

    # JS generic is the only app included in CCF install
    args.package = "libjs_generic"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.jwt_key_refresh_interval_s = 1

    # Hardcoded because host only accepts from info on release builds
    args.host_log_level = "info"

    repo = infra.gh_helper.Repository()
    env = cimetrics.env.get_env()

    compatibility_report = {}
    compatibility_report["version"] = args.ccf_version
    compatibility_report["live compatibility"] = {}
    previous_lts_version = run_live_compatibility_with_previous(args, repo, env)
    compatibility_report["live compatibility"].update(
        {"with previous": previous_lts_version}
    )
    next_lts_version = run_live_compatibility_with_next(args, repo, env)
    compatibility_report["live compatibility"].update({"with next": next_lts_version})

    # run_ledger_compatibility_since_first(args, use_snapshot=False)
    # run_ledger_compatibility_since_first(args, use_snapshot=True)

    # TODO: Publish compatibility report to Azure Pipelines
    if args.compatibility_report_file:
        with open(args.compatibility_report_file, "w") as f:
            json.dump(compatibility_report, f, indent=2)
            LOG.info(
                f"Compatibility report written to {args.compatibility_report_file}"
            )

    LOG.success(f"Compatibility report:\n {json.dumps(compatibility_report, indent=2)}")
