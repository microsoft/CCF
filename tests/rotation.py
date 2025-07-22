# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import reconfiguration

from loguru import logger as LOG


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        # Replace primary repeatedly and check the network still operates
        LOG.info(f"Retiring primary {args.rotation_retirements} times")
        for i in range(args.rotation_retirements):
            LOG.warning(f"Retirement {i}")
            reconfiguration.test_add_node(network, args)
            reconfiguration.test_retire_primary(network, args)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--rotation-retirements",
            help="Number of times to retire the primary",
            type=int,
            default=2,
        )

    args = infra.e2e_args.cli_args(add=add)
    args.package = "samples/apps/logging/logging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.initial_member_count = 1
    run(args)
