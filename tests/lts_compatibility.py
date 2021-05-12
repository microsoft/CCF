# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.proc
import infra.logging_app as app
import infra.utils
import json
import os
import requests
import re

from loguru import logger as LOG

LTS_INSTALL_DIRECTORY_PREFIX = "ccf_lts_"
GITHUB_RELEASE_API_BASE_URL = "https://api.github.com/repos/microsoft/CCF/releases"


# TODO: Test recovery since the very first LTS!


def install_release(version):
    deb_package_name = f"ccf_{version}_amd64.deb"
    install_directory = f"ccf_{version}"

    download_cmd = [
        "wget",
        f"https://github.com/microsoft/CCF/releases/download/ccf-{version}/{deb_package_name}",
    ]
    LOG.info(f"Downloading CCF release {version}...")
    infra.proc.ccall(*download_cmd, log_output=False)
    LOG.info("Unpacking debian package...")

    install_cmd = [
        "dpkg-deb",
        "-R",
        deb_package_name,
        install_directory,
    ]
    infra.proc.ccall(*install_cmd, log_output=False)

    install_path = os.path.abspath(os.path.join(install_directory, "opt/ccf"))

    LOG.success(f"CCF release {version} successfully installed at {install_path}")

    return install_path


def run_live_compatibility_since_last(args, latest_lts_release):
    """
    Test that a service from the previous LTS can be safely upgraded to the current version.
    """

    # First, install the latest LTS
    install_path = install_release(latest_lts_release)

    txs = app.LoggingTxs()

    library_dir = os.path.join(install_path, "lib")

    # Run a short-lived service from this LTS
    with infra.network.network(
        args.nodes,
        binary_directory=os.path.join(install_path, "bin"),
        library_directory=library_dir,
        dbg_nodes=args.debug_nodes,
        pdb=args.pdb,
        txs=txs,
        version="1.0",
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
            assert False, "No new primary should be elected"
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


def run_ledger_compatibility_since_first(args, lts_releases):

    # TODO:
    # 1. Install very first LTS release
    # 2. Run a service and issue some commands
    # 3. Stop
    # 4. Install next LTS release
    # 5. Rinse and repeat

    install_release()


def read_lts_releases_from_file(lts_release_file):
    lts_releases = []
    for l in open(lts_release_file, "r"):
        line = l.strip()
        if not line.startswith("#"):  # Ignore comments
            lts_releases.append(l.rstrip())
    return lts_releases


# TODO: Use PyGithub?
def get_latest_lts_info(lts_release):
    lts_release_re = "^ccf-{}$".format(lts_release.replace(".x", "\\.\\d+.\\d+"))
    all_releases = requests.get(GITHUB_RELEASE_API_BASE_URL)
    matching_releases = {}
    for release in json.loads(all_releases.content):
        if re.match(lts_release_re, release["tag_name"]):
            matching_releases[release["id"]] = release

    return matching_releases[sorted(matching_releases)[0]]


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--lts-releases-file",
            help="File containing the list of LTS releases so far",
            type=str,
        )

    args = infra.e2e_args.cli_args(add)

    lts_releases = read_lts_releases_from_file(args.lts_releases_file)

    if not lts_releases:
        raise ValueError(f"No valid LTS releases in {args.lts_releases_file} file")

    LOG.info(
        f'Testing compatibility against the LTS releases: {",".join(lts_releases)}'
    )

    LOG.success(get_latest_lts_info(lts_releases[0]))

    # JS generic is the only app included in CCF install
    args.package = "libjs_generic"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)

    # TODO: Hardcoded because host only accepts from info on release builds
    args.host_log_level = "info"

    run_live_compatibility_since_last(args, lts_releases[0])
    # run_ledger_compatibility_since_first(args, lts_releases)