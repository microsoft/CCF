# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.proc
import infra.logging_app as app
import infra.utils
import infra.gh_helper
import os
from setuptools.extern.packaging.version import Version  # type: ignore

import ccf.ledger


from loguru import logger as LOG


# TODO:
# 1. Test recovery since the very first LTS
# 2. Test live compatibility on all releases on a release branch
# 3.


def run_live_compatibility_since_last(args, lts_major_version, lts_install_path):
    """
    Test that a service from the previous LTS can be safely upgraded to the version of the local checkout
    """

    binary_dir = os.path.join(lts_install_path, "bin")
    library_dir = os.path.join(lts_install_path, "lib")

    # Run a short-lived service from this LTS
    txs = app.LoggingTxs()
    with infra.network.network(
        args.nodes,
        binary_directory=binary_dir,
        library_directory=library_dir,
        dbg_nodes=args.debug_nodes,
        pdb=args.pdb,
        txs=txs,
        version=lts_major_version,  # Start a service the LTS way
    ) as network:
        network.start_and_join(args)

        old_nodes = network.get_joined_nodes()
        primary, _ = network.find_primary()

        txs.issue(network, number_txs=args.snapshot_tx_interval * 4)

        old_code_id = infra.utils.get_code_id(
            args.enclave_type, args.oe_binary, args.package, library_dir=library_dir
        )
        new_code_id = infra.utils.get_code_id(
            args.enclave_type, args.oe_binary, args.package, library_dir="."
        )
        LOG.info(f"Initiating code upgrade from {old_code_id} to {new_code_id}")

        network.consortium.add_new_code(primary, new_code_id)

        # Add one more node than the current count so that at least one new
        # node is required to reach consensus
        # Note: alternate between joining from snapshot and replaying entire ledger
        from_snapshot = True
        for _ in range(0, len(network.get_joined_nodes()) + 1):
            new_node = network.create_and_trust_node(
                os.path.join(library_dir, args.package),
                "local://localhost",
                args,
                from_snapshot=from_snapshot,
            )
            assert new_node
            from_snapshot = not from_snapshot

        # The hybrid service can make progress
        txs.issue(network, number_txs=5)

        # Elect a new node as one of the primary
        for node in old_nodes:
            node.suspend()

        new_primary, _ = network.wait_for_new_primary(primary)

        for node in old_nodes:
            node.resume()

        try:
            network.wait_for_new_primary(new_primary)
            assert False, "No new primary should be elected while"
        except TimeoutError:
            pass

        # Retire one new node, so that at least one node is required to reach consensus
        other_new_nodes = [
            node
            for node in network.get_joined_nodes()
            if (node is not new_primary and node not in old_nodes)
        ]
        network.retire_node(new_primary, other_new_nodes[0])

        txs.issue(network, number_txs=5)

        # TODO:
        # - Retire old nodes and remove old code


def run_ledger_compatibility_since_first(args):
    repo = infra.gh_helper.Repository()
    lts_releases = repo.get_lts_releases()

    # TODO: Remove fakeness
    lts_releases_fake = {}
    lts_releases_fake["1.0"] = lts_releases["release/1.x"]
    lts_releases_fake["2.0"] = lts_releases["release/1.x"]

    lts_releases_fake["local"] = None

    # TODO: Also test local checkout!
    txs = app.LoggingTxs()
    is_first = True
    for _, lts_release in lts_releases_fake.items():

        if lts_release:
            version, install_path = repo.install_release(lts_release)
            binary_dir = os.path.join(install_path, "bin")
            library_dir = os.path.join(install_path, "lib")
            major_version = Version(version).release[0]
        else:
            version = args.ccf_version
            binary_dir = "."
            library_dir = "."
            major_version = None

        network_args = {
            "hosts": args.nodes,
            "binary_dir": binary_dir,
            "library_dir": library_dir,
            "txs": txs,
            "version": major_version,
        }
        if is_first:
            network = infra.network.Network(**network_args)
            network.start_and_join(args)
            is_first = False
        else:
            network = infra.network.Network(**network_args, existing_network=network)
            network.start_in_recovery(
                args,
                ledger_dir,
                committed_ledger_dir,
                # snapshot_dir=snapshot_dir, # TODO: Include snapshots too?
            )
            network.recover(args)

        nodes = network.get_joined_nodes()

        # Verify that nodes run the expected CCF version
        if not major_version or major_version > 1:
            for node in nodes:
                with node.client() as c:
                    r = c.get("/node/version")
                    assert r.body.json()["ccf_version"] == version

        txs.issue(network, number_txs=5)

        network.stop_all_nodes()

        ledger_dir, committed_ledger_dir = nodes[0].get_ledger(
            include_read_only_dirs=True
        )

        # Check that the ledger can be parsed on all nodes
        for node in nodes:
            public_state = ccf.ledger.Ledger(
                node.remote.ledger_paths()
            ).get_latest_public_state()
            LOG.warning(list(public_state[0].keys()))


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--previous-lts-file",
            help="File containing the latest LTS",
            type=str,
        )

    args = infra.e2e_args.cli_args(add)

    # JS generic is the only app included in CCF install
    args.package = "libjs_generic"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)

    # Hardcoded because host only accepts from info on release builds
    args.host_log_level = "info"

    # repo = infra.gh_helper.Repository()
    # lts_major_version, lts_install_path = repo.install_latest_lts(
    #     args.previous_lts_file
    # )

    # LOG.error(f"LTS version: {lts_major_version}")

    # run_live_compatibility_since_last(args, lts_major_version, lts_install_path)
    # run_ledger_compatibility_since_first(args, lts_releases)

    run_ledger_compatibility_since_first(args)