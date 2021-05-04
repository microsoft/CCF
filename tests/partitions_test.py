# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.network
import infra.e2e_args
import infra.partitions
import infra.logging_app as app
import time

from loguru import logger as LOG


def run(args):
    txs = app.LoggingTxs()
    partitioner = infra.partitions.Partitioner()

    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_join(args)

        # TODO:
        # 1. Add partition capability
        # 2. Test bi-directions
        # 3. Cleanup rules as much as possible

        nodes = network.get_joined_nodes()
        # partitioner.isolate_node(nodes[0])
        # partitioner.isolate_node_from_other(nodes[0], nodes[1])
        # partitioner.create_partition(network, [nodes[1], nodes[2]])

        # Test impossible partition cases
        try:
            partitioner.create_partition(
                network,
                [nodes[0], nodes[2]],
                [nodes[1], nodes[2]],
            )
            assert False, "Node should not appear in two or more partitions"
        except ValueError:
            pass

        try:
            partitioner.create_partition(network)
            assert False, "At least one partition should be specified"
        except ValueError:
            pass

        try:
            new_node = infra.node.Node(-1, "local://localhost")
            partitioner.create_partition(network, [new_node])
            assert False, "All nodes should belong to network"
        except ValueError:
            pass

        input("")
        # partitioner.create_partition(network, [nodes[0], nodes[1]])
        # nodes[0].n2n_isolate_from_service()

        # try:
        #     while True:
        #         time.sleep(60)

        # except KeyboardInterrupt:
        #     LOG.info("Stopping all CCF nodes...")


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "liblogging"

    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run(args)