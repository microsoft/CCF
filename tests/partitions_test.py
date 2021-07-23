# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.network
import infra.e2e_args
import infra.partitions
import infra.logging_app as app
import suite.test_requirements as reqs
from infra.checker import check_can_progress, check_does_not_progress
import pprint
from ccf.tx_status import TxStatus


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
    network.wait_for_all_nodes_to_commit(primary=primary)

    # The primary should remain stable while the partition is active
    # Note: Context manager
    with network.partitioner.partition(partition):
        try:
            network.wait_for_new_primary(primary)
            assert False, "No new primary should be elected when partitioning majority"
        except TimeoutError:
            pass

    # A new leader should be elected once the partition is dropped
    network.wait_for_new_primary(primary)

    return network


@reqs.description("Isolate primary from one backup")
def test_isolate_primary_from_one_backup(network, args):
    primary, backups = network.find_nodes()

    # Issue one transaction, waiting for all nodes to be have reached
    # the same level of commit, so that nodes outside of partition can
    # become primary after this one is dropped
    # Note: Because of https://github.com/microsoft/CCF/issues/2224, we need to
    # issue a write transaction instead of just reading the TxID of the latest entry
    network.txs.issue(network)

    # Isolate first backup from primary so that first backup becomes candidate
    # in a new term and wins the election
    # Note: Managed manually
    rules = network.partitioner.isolate_node(primary, backups[0])

    new_primary, new_view = network.wait_for_new_primary(
        primary, nodes=backups, timeout_multiplier=6
    )

    # Explicitly drop rules before continuing
    rules.drop()

    # Old primary should now report of the new primary
    new_primary_, new_view_ = network.wait_for_new_primary(primary, nodes=[primary])
    assert (
        new_primary == new_primary_
    ), f"New primary {new_primary_.local_node_id} after partition is dropped is different than before {new_primary.local_node_id}"
    assert (
        new_view == new_view_
    ), f"Consensus view {new_view} should not changed after partition is dropped: no {new_view_}"

    return network


@reqs.description("Isolate and reconnect primary")
def test_isolate_and_reconnect_primary(network, args):
    primary, backups = network.find_nodes()
    with network.partitioner.partition(backups):
        lost_tx_resp = check_does_not_progress(primary)

        new_primary, _ = network.wait_for_new_primary(
            primary, nodes=backups, timeout_multiplier=6
        )
        new_tx_resp = check_can_progress(new_primary)

    # Check reconnected former primary has caught up
    with primary.client() as c:
        try:
            c.wait_for_commit(new_tx_resp, timeout=5)
        except TimeoutError:
            details = c.get("/node/consensus").body.json()
            assert (
                False
            ), f"Stuck before {new_tx_resp.view}.{new_tx_resp.seqno}: {pprint.pformat(details)}"

        # Check it has dropped anything submitted while partitioned
        r = c.get(f"/node/tx?transaction_id={lost_tx_resp.view}.{lost_tx_resp.seqno}")
        status = TxStatus(r.body.json()["status"])
        assert status == TxStatus.Invalid, r


def run(args):
    txs = app.LoggingTxs("user0")

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
        test_isolate_primary_from_one_backup(network, args)
        for _ in range(5):
            test_isolate_and_reconnect_primary(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "liblogging"

    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run(args)
