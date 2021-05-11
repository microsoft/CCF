# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.proc
import infra.logging_app as app
import infra.utils
import os

from loguru import logger as LOG

LTS_INSTALL_DIRECTORY_PREFIX = "ccf_lts_"

# TODO: Use https://api.github.com/repos/microsoft/CCF/releases to retrieve latest 1.x release
LATEST_LTS = "1.0.0"


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


def run(args):

    # First, install the latest LTS
    install_path = install_release(LATEST_LTS)

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
    ) as network:
        network.start_and_join(args)
        primary, _ = network.find_primary()

        txs.issue(network, number_txs=5)

        old_code_id = infra.utils.get_code_id(
            args.enclave_type, args.oe_binary, args.package, library_dir=library_dir
        )
        new_code_id = infra.utils.get_code_id(
            args.enclave_type, args.oe_binary, args.package, library_dir="."
        )
        LOG.info(f"Initiating code upgrade from {old_code_id} to {new_code_id}")

        network.consortium.add_new_code(primary, new_code_id)

        for _ in range(0, len(network.get_joined_nodes())):
            new_node = network.create_and_trust_node(
                os.path.join(library_dir, args.package), "local://localhost", args
            )
            assert new_node

    # txs = app.LoggingTxs()
    # with infra.network.network(
    #     args.nodes,
    #     args.binary_dir,
    #     args.debug_nodes,
    #     args.perf_nodes,
    #     pdb=args.pdb,
    #     txs=txs,
    # ) as network:
    #     pass
    # TODO:
    # 1. Download latest LTS, that has to be hardcoded somewhere as cannot be deduced from git tag
    # 2. Run service with cchost + libjsgeneric (enough for at least two chunks?)
    # 3. Add newly built nodes and perform code upgrade
    # 4. Primary change halfway through
    #

    # Recovery
    # 4. Kill service, perform recovery


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()

    # JS generic is the only enclave shipped in the CCF install
    args.package = "libjs_generic"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)

    # TODO: Hardcoded because host only accepts from info on release builds
    args.host_log_level = "info"
    run(args)