# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.network
import infra.net
import infra.interfaces
import infra.e2e_args
import infra.partitions
import infra.logging_app as app
import suite.test_requirements as reqs
from infra.checker import check_can_progress, check_does_not_progress
import pprint
from infra.tx_status import TxStatus
import time
import http
import contextlib

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
@reqs.exactly_n_nodes(3)
def test_isolate_primary_from_one_backup(network, args):
    p, backups = network.find_nodes()
    b_0, b_1 = backups

    # Issue one transaction, waiting for all nodes to be have reached
    # the same level of commit, so that nodes outside of partition can
    # become primary after this one is dropped
    # Note: Because of https://github.com/microsoft/CCF/issues/2224, we need to
    # issue a write transaction instead of just reading the TxID of the latest entry
    initial_txid = network.txs.issue(network)

    # Isolate first backup from primary so that first backup becomes candidate
    # in a new term and wins the election
    # Note: Managed manually
    rules = network.partitioner.isolate_node(p, b_0)

    # Now wait for several elections to occur. We expect:
    # - b_0 to call and win an election with b_1's help
    # - b_0 to produce a new signature, and commit it with b_1's help
    # - p to call its own election, and lose because it doesn't have this signature
    # - In the resulting election race:
    #   - If p calls first, it loses and we're in the same situation
    #   - If b_0 calls first, it wins, but then p calls its election and we've returned to the same situation
    #   - If b_1 calls first, it can win and then bring _both_ nodes up-to-date, becoming a _stable_ primary
    # So we repeat elections until b_1 is primary

    new_primary = network.wait_for_primary_unanimity(
        min_view=initial_txid.view, timeout_multiplier=30
    )
    assert new_primary == b_1

    new_view = network.txs.issue(network).view

    # The partition is now between 2 backups, but both can talk to the new primary
    # Explicitly drop rules before continuing
    rules.drop()

    # Original primary should now, or very soon, report the new primary
    new_primary_, new_view_ = network.wait_for_new_primary(p, nodes=[p])
    assert (
        new_primary == new_primary_
    ), f"New primary {new_primary_.local_node_id} after partition is dropped is different than before {new_primary.local_node_id}"
    assert (
        new_view == new_view_
    ), f"Consensus view {new_view} should not have changed after partition is dropped: now {new_view_}"

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


@reqs.description("New joiner helps liveness")
@reqs.exactly_n_nodes(3)
def test_new_joiner_helps_liveness(network, args):
    primary, backups = network.find_nodes()

    # Issue some transactions, so there is a ledger history that a new node must receive
    network.txs.issue(network, number_txs=10)

    # Remove a node, leaving the network frail
    network.retire_node(primary, backups[-1])
    backups[-1].stop()

    primary, backups = network.find_nodes()

    with contextlib.ExitStack() as stack:
        # Add a new node, but partition them before trusting them
        new_node = network.create_node("local://localhost")
        network.join_node(new_node, args.package, args, from_snapshot=False)
        new_joiner_partition = [new_node]
        new_joiner_rules = stack.enter_context(
            network.partitioner.partition([primary, *backups], new_joiner_partition)
        )

        # Trust the new node, and wait for commit of this (but don't ask the new node itself, which doesn't know this yet)
        network.trust_node(new_node, args, no_wait=True)
        check_can_progress(primary)

        # Partition the primary, temporarily creating a minority service that cannot make progress
        minority_partition = backups[len(backups) // 2 :] + new_joiner_partition
        minority_rules = stack.enter_context(
            network.partitioner.partition(minority_partition)
        )
        # This is an unusual situation, where we've actually produced a dead partitioned node.
        # Initially any write requests will timeout (failed attempt at forwarding), and then
        # the node transitions to a candidate with nobody to talk to. Rather than trying to
        # catch the errors of these states quickly, we just sleep until the latter state is
        # reached, and then confirm it was reached.
        time.sleep(network.observed_election_duration)
        with backups[0].client("user0") as c:
            r = c.post("/app/log/private", {"id": 42, "msg": "Hello world"})
            assert r.status_code == http.HTTPStatus.SERVICE_UNAVAILABLE

        # Restore the new node to the service
        new_joiner_rules.drop()

        # Confirm that the new node catches up, and progress can be made in this majority partition
        network.wait_for_new_primary(primary, minority_partition)
        check_can_progress(new_node)

        # Explicitly drop rules before continuing
        minority_rules.drop()

        network.wait_for_primary_unanimity()
        primary, _ = network.find_nodes()
        network.wait_for_all_nodes_to_commit(primary=primary)


@reqs.description("Add a learner, partition nodes, check that there is no progress")
def test_learner_does_not_take_part(network, args):
    primary, backups = network.find_nodes()
    f_backups = backups[: network.get_f() + 1]

    # Note: host is supplied explicitly to avoid having differently
    # assigned IPs for the interfaces, something which the test infra doesn't
    # support widely yet.
    operator_rpc_interface = "operator_rpc_interface"
    host = infra.net.expand_localhost()
    new_node = network.create_node(
        infra.interfaces.HostSpec(
            rpc_interfaces={
                infra.interfaces.PRIMARY_RPC_INTERFACE: infra.interfaces.RPCInterface(
                    host=host
                ),
                operator_rpc_interface: infra.interfaces.RPCInterface(
                    host=host,
                    endorsement=infra.interfaces.Endorsement(authority="Node"),
                ),
            }
        )
    )
    network.join_node(new_node, args.package, args, from_snapshot=False)

    LOG.info("Wait for all nodes to have committed join of new pending node")
    network.wait_for_all_nodes_to_commit(primary=primary)

    # Here, we partition a majority of backups. This is very intentional so that
    # the new learner node is not promoted to trusted while the partition is up.
    # However, this means that the isolated majority of backups can (and will)
    # elect one of them as new primary while the partition is up. When the partition
    # is lifted, all the transactions executed of the primary node (including
    # trusting the new node) will be rolled back. Because of this, we issue a new
    # trust_node proposal to make sure the new node ends up being trusted and joins
    # successfully.
    with network.partitioner.partition(f_backups):

        check_does_not_progress(primary, timeout=5)

        try:
            network.consortium.trust_node(
                primary,
                new_node.node_id,
                timeout=ceil(args.join_timer_s * 2),
                valid_from=str(infra.crypto.datetime_to_X509time(datetime.now())),
            )
        except TimeoutError:
            LOG.info("Trust node proposal did not commit as expected")
        else:
            raise Exception("Trust node proposal committed unexpectedly")

        check_does_not_progress(primary, timeout=5)

        LOG.info("Majority partition can make progress")
        partition_primary, _ = network.wait_for_new_primary(primary, nodes=f_backups)
        check_can_progress(partition_primary)

        LOG.info("New joiner is not promoted to Trusted without f other backups")
        with new_node.client(
            interface_name=operator_rpc_interface, self_signed_ok=True
        ) as c:
            r = c.get("/node/network/nodes/self")
            assert r.body.json()["status"] == "Learner"
            r = c.get("/node/consensus")
            assert new_node.node_id in r.body.json()["details"]["learners"]

    LOG.info("Partition is lifted, wait for primary unanimity on original nodes")
    # Note: Because trusting the new node failed, the new node is not considered
    # in the primary unanimity. Indeed, its transition to Trusted may have been rolled back.
    primary = network.wait_for_primary_unanimity()
    network.wait_for_all_nodes_to_commit(primary=primary)

    LOG.info("Trust new joiner again")
    network.trust_node(new_node, args)

    check_can_progress(primary)
    check_can_progress(new_node)


def run_2tx_reconfig_tests(args):
    if not args.include_2tx_reconfig:
        return

    local_args = args

    if args.reconfiguration_type != "TwoTransaction":
        local_args.reconfiguration_type = "TwoTransaction"

    with infra.network.network(
        local_args.nodes,
        local_args.binary_dir,
        local_args.debug_nodes,
        local_args.perf_nodes,
        pdb=local_args.pdb,
        init_partitioner=True,
    ) as network:
        network.start_and_open(local_args)

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
        network.start_and_open(args)

        test_invalid_partitions(network, args)
        test_partition_majority(network, args)
        test_isolate_primary_from_one_backup(network, args)
        test_new_joiner_helps_liveness(network, args)
        for n in range(5):
            test_isolate_and_reconnect_primary(network, args, iteration=n)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--include-2tx-reconfig",
            help="Include tests for the 2-transaction reconfiguration scheme",
            default=False,
            action="store_true",
        )

    args = infra.e2e_args.cli_args(add)
    args.package = "samples/apps/logging/liblogging"

    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run(args)
    run_2tx_reconfig_tests(args)
