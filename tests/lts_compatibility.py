# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.proc
import infra.logging_app as app
import infra.utils
import os
import re
from github import Github

from loguru import logger as LOG


# TODO: Test recovery since the very first LTS!

# This assumes that CCF is installed at `/opt/ccf`, which is true from 1.0.0
INSTALL_DIRECTORY_SUB_PATH = "opt/ccf"


def install_ccf_debian_package(debian_package_url, directory_name):
    LOG.info(f"Downloading {debian_package_url}...")
    download_cmd = ["wget", debian_package_url]
    assert (
        infra.proc.ccall(*download_cmd, log_output=False).returncode == 0
    ), "Download failed"

    LOG.info("Unpacking debian package...")
    remove_cmd = ["rm", "-rf", directory_name]
    assert (
        infra.proc.ccall(*remove_cmd).returncode == 0
    ), "Previous install cleanup failed"
    install_cmd = ["dpkg-deb", "-R", debian_package_url.split("/")[-1], directory_name]
    assert infra.proc.ccall(*install_cmd).returncode == 0, "Installation failed"

    install_path = os.path.abspath(
        os.path.join(directory_name, INSTALL_DIRECTORY_SUB_PATH)
    )
    LOG.success(f"CCF release successfully installed at {install_path}")
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


BRANCH_RELEASE_PREFIX = "release/"
REPOSITORY_NAME = "microsoft/CCF"
DEBIAN_PACKAGE_EXTENSION = "_amd64.deb"


def get_release_branches_names(repo):
    # TODO: Branches should be sorted chronologically
    # Release branches are sorted alphabetically
    return sorted(
        [
            branch.name
            for branch in repo.get_branches()
            if branch.name.startswith(BRANCH_RELEASE_PREFIX)
        ]
    )


def get_releases_from_release_branch(repo, branch_name):
    # Assumes that N.a.b releases can only be cut from N.x branch, with N a valid major version number
    assert branch_name.startswith(
        BRANCH_RELEASE_PREFIX
    ), f"{branch_name} is not a release branch"

    release_branch_name = branch_name[len(BRANCH_RELEASE_PREFIX) :]
    release_re = "^ccf-{}$".format(release_branch_name.replace(".x", "([.\d+]+)"))

    # Most recent tag is first
    return list(([tag for tag in repo.get_tags() if re.match(release_re, tag.name)]))


if __name__ == "__main__":

    # TODO: Delete this file?
    def add(parser):
        parser.add_argument(
            "--lts-releases-file",
            help="File containing the list of LTS releases so far",
            type=str,
        )

    args = infra.e2e_args.cli_args(add)

    g = Github("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")
    repo = g.get_repo(REPOSITORY_NAME)

    # TODO: How do we select the latest tag for the branch this currently runs on?

    release_branches = get_release_branches_names(repo)
    LOG.info(f"Release branches: {release_branches}")

    latest_release_branch = "release/0.99.x"  # TODO: To deduce from local checkout
    LOG.info(f"Latest release branch for this checkout: {latest_release_branch}")

    tags_for_this_release = get_releases_from_release_branch(
        repo, latest_release_branch
    )
    LOG.info(f"Found tags: {[t.name for t in tags_for_this_release]}")

    latest_tag_for_this_release = tags_for_this_release[0]
    LOG.info(f"Most recent tag: {latest_tag_for_this_release.name}")

    releases = [
        r for r in repo.get_releases() if r.tag_name == latest_tag_for_this_release.name
    ]
    assert (
        len(releases) == 1
    ), f"Found {len(releases)} releases for tag {latest_tag_for_this_release.name}, expected 1"
    release = releases[0]

    LOG.info(f"Found release: {release.html_url}")

    stripped_tag = latest_tag_for_this_release.name[len("ccf-") :]
    debian_package_url = [
        a.browser_download_url
        for a in release.get_assets()
        if re.match(f"ccf_{stripped_tag}{DEBIAN_PACKAGE_EXTENSION}", a.name)
    ][0]

    install_path = install_ccf_debian_package(
        debian_package_url,
        directory_name=f"ccf_install_{latest_tag_for_this_release.name}",
    )

    # for release in repo.get_releases():
    # if release.

    # TODO: Get release for this tag

    # lts_releases = read_lts_releases_from_file(args.lts_releases_file)

    # if not lts_releases:
    #     raise ValueError(f"No valid LTS releases in {args.lts_releases_file} file")

    # LOG.info(
    #     f'Testing compatibility against the LTS releases: {",".join(lts_releases)}'
    # )

    # LOG.success(get_latest_lts_info(lts_releases[0]))

    # # JS generic is the only app included in CCF install
    # args.package = "libjs_generic"
    # args.nodes = infra.e2e_args.max_nodes(args, f=0)

    # # TODO: Hardcoded because host only accepts from info on release builds
    # args.host_log_level = "info"

    # run_live_compatibility_since_last(args, lts_releases[0])
    # run_ledger_compatibility_since_first(args, lts_releases)