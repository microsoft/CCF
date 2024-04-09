# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.e2e_args
import tvc


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        targets = [
            f"https://{n.get_public_rpc_address()}" for n in network.get_joined_nodes()
        ]
        tvc.run(targets, network.cert_path, 100)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "libjs_generic"
    args.js_app_bundle = "../samples/apps/basic_tv/js/"
    args.nodes = infra.e2e_args.nodes(args, 5)
    run(args)
