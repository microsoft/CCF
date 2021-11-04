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

from loguru import logger as LOG

from math import ceil
from datetime import datetime


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
    initial_view = None
    with network.partitioner.partition(partition):
        try:
            network.wait_for_new_primary(primary)
            assert False, "No new primary should be elected when partitioning majority"
        except TimeoutError:
            LOG.info("No new primary, as expected")
            with primary.client() as c:
                res = c.get("/node/network")  # Well-known read-only endpoint
                body = res.body.json()
                initial_view = body["current_view"]

    # The partitioned nodes will have called elections, increasing their view.
    # When the partition is lifted, the nodes must elect a new leader, in at least this
    # increased term. The winning node could come from either partition, and could even
    # be the original primary.
    network.wait_for_primary_unanimity(min_view=initial_view)

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
def test_isolate_and_reconnect_primary(network, args, **kwargs):
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
            # There will be at least one full election cycle for nothing, where the
            # re-joining node fails to get elected but causes others to rev up their
            # term. After that, a successful election needs to take place, and we
            # arbitrarily allow 3 time periods to avoid being too brittle when
            # raft timeouts line up badly.
            c.wait_for_commit(new_tx_resp, timeout=(network.election_duration * 4))
        except TimeoutError:
            details = c.get("/node/consensus").body.json()
            assert (
                False
            ), f"Stuck before {new_tx_resp.view}.{new_tx_resp.seqno}: {pprint.pformat(details)}"

        # Check it has dropped anything submitted while partitioned
        r = c.get(f"/node/tx?transaction_id={lost_tx_resp.view}.{lost_tx_resp.seqno}")
        status = TxStatus(r.body.json()["status"])
        assert status == TxStatus.Invalid, r


@reqs.description("Add a learner, partition nodes, check that there is no progress")
def test_learner_does_not_take_part(network, args):
    primary, backups = network.find_nodes()
    f_backups = backups[: network.get_f() + 1]

    new_node = network.create_node("local://localhost")
    network.join_node(new_node, args.package, args, from_snapshot=False)

    with network.partitioner.partition(f_backups):

        check_does_not_progress(primary, timeout=5)

        try:
            network.consortium.trust_node(
                primary,
                new_node.node_id,
                timeout=ceil(args.join_timer * 2 / 1000),
                valid_from=str(infra.crypto.datetime_to_X509time(datetime.now())),
            )
            new_node.wait_for_node_to_join(timeout=ceil(args.join_timer * 2 / 1000))
            join_failed = False
        except Exception:
            join_failed = True

        if not join_failed:
            raise Exception("join succeeded unexpectedly")

        with new_node.client(self_signed_ok=True) as c:
            r = c.get("/node/network/nodes/self")
            assert r.body.json()["status"] == "Learner"
            r = c.get("/node/consensus")
            assert new_node.node_id in r.body.json()["details"]["learners"]

        # New node joins, but cannot be promoted to TRUSTED without f other backups

        check_does_not_progress(primary, timeout=5)

        with new_node.client(self_signed_ok=True) as c:
            r = c.get("/node/network/nodes/self")
            assert r.body.json()["status"] == "Learner"
            r = c.get("/node/consensus")
            assert new_node.node_id in r.body.json()["details"]["learners"]

    network.wait_for_primary_unanimity()
    primary, _ = network.find_nodes()
    network.wait_for_all_nodes_to_commit(primary=primary)
    check_can_progress(primary)


def run_2tx_reconfig_tests(args):
    if not args.include_2tx_reconfig:
        return

    local_args = args

    if args.reconfiguration_type != "2tx":
        local_args.reconfiguration_type = "2tx"

    with infra.network.network(
        local_args.nodes,
        local_args.binary_dir,
        local_args.debug_nodes,
        local_args.perf_nodes,
        pdb=local_args.pdb,
        init_partitioner=True,
    ) as network:
        network.start_and_join(local_args)

        test_learner_does_not_take_part(network, local_args)


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
        for n in range(5):
            test_isolate_and_reconnect_primary(network, args, iteration=n)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--include-2tx-reconfig",
            help="Include tests for the 2-transaction reconfiguration scheme",
            action="store_true",
        )

    args = infra.e2e_args.cli_args(add)
    args.package = "samples/apps/logging/liblogging"

    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run(args)
    run_2tx_reconfig_tests(args)
