# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.network
import infra.e2e_args
import infra.partitions
import infra.logging_app as app
import suite.test_requirements as reqs


@reqs.description("Invalid partitions are not allowed")
def test_invalid_partitions(network, args):
    nodes = network.get_joined_nodes()

    try:
        network.partitioner.partition(
            [nodes[0], nodes[2]],
            [nodes[1], nodes[2]],
        )
        assert False, "Node should not appear in two or more partitions"
    except ValueError:
        pass

    try:
        network.partitioner.partition()
        assert False, "At least one partition should be specified"
    except ValueError:
        pass

    try:
        invalid_local_node_id = -1
        new_node = infra.node.Node(invalid_local_node_id, "local://localhost")
        network.partitioner.partition([new_node])
        assert False, "All nodes should belong to network"
    except ValueError:
        pass

    return network


@reqs.description("Partition primary + f nodes")
def test_partition_majority(network, args):
    primary, backups = network.find_nodes()

    # Create a partition with primary + half remaining nodes (i.e. majority)
    partition = [primary]
    partition.extend(backups[len(backups) // 2 :])

    # Wait for all nodes to be have reached the same level of commit, so that
    # nodes outside of partition can become primary after this one is dropped
    network.wait_for_node_commit_sync()

    # The primary should remain stable while the partition is active
    # Note: Context manager
    with network.partitioner.partition(partition):
        try:
            network.wait_for_new_primary(primary.node_id)
            assert False, "No new primary should be elected when partitioning majority"
        except TimeoutError:
            pass

    # A new leader should be elected once the partition is dropped
    network.wait_for_new_primary(primary.node_id)

    return network


@reqs.description("Isolate primary from one backup")
def test_isolate_primary(network, args):
    primary, backups = network.find_nodes()

    # Isolate first backup from primary so that first backup becomes candidate
    # in a new term and wins the election
    # Note: Managed manually
    rules = network.partitioner.isolate_node(primary, backups[0])

    network.wait_for_new_primary(primary.node_id, nodes=backups, timeout_multiplier=6)

    # Explicitly drop rules before continuing
    rules.drop()

    return network


def run(args):
    txs = app.LoggingTxs()

    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
        init_partitioner=True,
    ) as network:
        network.start_and_join(args)

        test_invalid_partitions(network, args)
        test_partition_majority(network, args)
        test_isolate_primary(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "liblogging"

    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run(args)
