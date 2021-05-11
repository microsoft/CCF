# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.proc
import infra.logging_app as app


def install_latest_lts():
    download_cmd = [
        "wget",
        "https://github.com/microsoft/CCF/releases/download/ccf-1.0.0/ccf_1.0.0_amd64.deb",
    ]
    infra.proc.ccall(*download_cmd)

    install_cmd = []


def run(args):

    txs = app.LoggingTxs()
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        pass
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
    if args.js_app_bundle:
        args.package = "libjs_generic"
    else:
        args.package = "liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    run(args)