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
import ccf.ledger

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

    LOG.info(
        f"Check that primary {p.local_node_id} reports increasing last ack time for partitioned backup {b_0.local_node_id}"
    )
    last_ack = 0
    while True:
        with p.client() as c:
            r = c.get("/node/consensus", log_capture=[]).body.json()["details"]
            ack = r["acks"][b_0.node_id]["last_received_ms"]
        if r["primary_id"] is not None:
            assert (
                ack >= last_ack
            ), f"Nodes {p.local_node_id} and {b_0.local_node_id} are no longer partitioned"
            last_ack = ack
        else:
            LOG.debug(f"Node {p.local_node_id} is no longer primary")
            break
        time.sleep(0.1)

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

    LOG.info(f"Check that new primary {new_primary.local_node_id} reports stable acks")
    last_ack = 0
    end_time = time.time() + 2 * network.args.election_timeout_ms // 1000
    while time.time() < end_time:
        with new_primary.client() as c:
            acks = c.get("/node/consensus", log_capture=[]).body.json()["details"][
                "acks"
            ]
            delayed_acks = [
                ack
                for ack in acks.values()
                if ack["last_received_ms"] > args.election_timeout_ms
            ]
            if delayed_acks:
                raise RuntimeError(f"New primary reported some delayed acks: {acks}")
        time.sleep(0.1)

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

    with primary.client() as c:
        primary_view = c.get("/node/consensus").body.json()["details"]["current_view"]

    with network.partitioner.partition(backups):
        lost_tx_resp = check_does_not_progress(primary)

        new_primary, _ = network.wait_for_new_primary(
            primary, nodes=backups, timeout_multiplier=6
        )
        new_tx_resp = check_can_progress(new_primary)

        # CheckQuorum: the primary node should automatically step
        # down if it has not heard back from a majority of backups.
        # However, it is not guaranteed that the transient follower state
        # will be observed, so wait for candidate state instead.
        # The isolated primary will stay in follower state once Pre-Vote
        # is implemented. https://github.com/microsoft/CCF/issues/2577
        primary.wait_for_leadership_state(
            primary_view, "Candidate", timeout=2 * args.election_timeout_ms / 1000
        )

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


@reqs.description("Test election while reconfiguration is in flight")
@reqs.at_least_n_nodes(3)
def test_election_reconfiguration(network, args):
    # Test for issue described in https://github.com/microsoft/CCF/issues/3948
    # Note: this test makes use of node-endorsed secondary RPC interface since
    # new nodes never observe commit of their configuration and thus never
    # open their service-endorsed primary RPC interface.
    primary, backups = network.find_nodes()

    LOG.info("Join new nodes without trusting them just yet")
    new_nodes = []
    # Start N+1 new nodes to make sure they cannot elect one of them as a primary
    # without approval from the original configuration
    for _ in range(len(network.nodes) + 1):
        rpc_interfaces = {
            infra.interfaces.PRIMARY_RPC_INTERFACE: infra.interfaces.RPCInterface(
                host="localhost"
            )
        }
        rpc_interfaces.update(infra.interfaces.make_secondary_interface())
        new_node = network.create_node(infra.interfaces.HostSpec(rpc_interfaces))
        network.join_node(new_node, args.package, args, from_snapshot=False)
        new_nodes.append(new_node)

    # Wait until all backups know about these joins, so they have an equal chance of
    # becoming primary afterwards
    network.wait_for_node_commit_sync()

    LOG.info("Isolate original backups and issue reconfiguration of another quorum")
    # Partition backups _from each other_
    with network.partitioner.partitions([backup] for backup in backups):
        LOG.info("Trust all new nodes in one single proposal")
        # Note: Commit is stuck since a majority of backups in initial configuration
        # are isolated
        network.consortium.trust_nodes(
            primary,
            [n.node_id for n in new_nodes],
            valid_from=datetime.utcnow(),
            wait_for_commit=False,
        )

        for node in new_nodes:
            node.wait_for_node_to_join(
                interface_name=infra.interfaces.SECONDARY_RPC_INTERFACE
            )
            # Wait for configuration tx to be replicated to new node
            network.wait_for_node_in_store(
                node,
                node.node_id,
                ccf.ledger.NodeStatus.TRUSTED,
                interface_name=infra.interfaces.SECONDARY_RPC_INTERFACE,
            )

        LOG.info(f"Stop primary node {primary.local_node_id} to trigger election")
        primary.stop()

        LOG.info(
            "Make sure that new nodes cannot elect a primary node among themselves"
        )
        try:
            network.wait_for_new_primary(
                primary,
                nodes=new_nodes,
                interface_name=infra.interfaces.SECONDARY_RPC_INTERFACE,
                timeout_multiplier=3,
            )
        except infra.network.PrimaryNotFound:
            LOG.info(
                "As expected, new primary could not be elected as old configuration could not make progress"
            )
        else:
            assert False, "No new primary should be elected while partition is up"

        LOG.info("Stop all new nodes")
        for node in new_nodes:
            node.stop()

    LOG.info(
        "As partition is lifted, check that isolated original backups elect primary"
    )
    network.wait_for_primary_unanimity(nodes=backups)

    LOG.info("Retire former primary and add new node")
    network.retire_node(backups[0], primary)
    new_node = network.create_node("local://localhost")
    network.join_node(new_node, args.package, args, from_snapshot=False)
    network.trust_node(new_node, args)

    return network


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
                    endorsement=infra.interfaces.Endorsement(
                        authority=infra.interfaces.EndorsementAuthority.Node
                    ),
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

        try:
            network.consortium.trust_node(
                primary,
                new_node.node_id,
                timeout=ceil(args.join_timer_s * 2),
                valid_from=datetime.utcnow(),
            )
        except TimeoutError:
            LOG.info("Trust node proposal did not commit as expected")
        else:
            raise Exception("Trust node proposal committed unexpectedly")

        LOG.info("Majority partition can make progress")
        partition_primary, _ = network.wait_for_new_primary(primary, nodes=f_backups)
        check_can_progress(partition_primary)

        LOG.info("New joiner is not promoted to Trusted without f other backups")
        with new_node.client(
            interface_name=operator_rpc_interface, verify_ca=False
        ) as c:
            r = c.get("/node/network/nodes/self")
            assert r.body.json()["status"] == "Learner"
            r = c.get("/node/consensus")
            assert new_node.node_id in r.body.json()["details"]["learners"]

    LOG.info("Partition is lifted, wait for primary unanimity on original nodes")
    # Note: Because trusting the new node failed, the new node is not considered
    # in the primary unanimity. Indeed, its transition to Trusted may have been rolled back.
    primary = network.wait_for_primary_unanimity(timeout_multiplier=30)
    network.wait_for_all_nodes_to_commit(primary=primary)

    LOG.info("Trust new joiner again")
    network.trust_node(new_node, args)

    check_can_progress(primary)
    check_can_progress(new_node)


@reqs.description("Forwarding across a partition may trigger a timeout")
@reqs.at_least_n_nodes(3)
def test_forwarding_timeout(network, args):
    primary, backups = network.find_nodes()
    backup = backups[0]
    key = 42
    val_a = "Hello"
    val_b = "Goodbye"

    with backup.client("user0") as c:
        LOG.info("Initial write request is forwarded and succeeds")
        r = c.post("/app/log/private", {"id": key, "msg": val_a})
        assert r.status_code == http.HTTPStatus.OK

        network.wait_for_all_nodes_to_commit(primary=primary)

    LOG.info("Cross-partition write request is forwarded and times out")
    with network.partitioner.partition(backups):
        with backup.client("user0") as c:
            # NB: Only fails if request happens soon after partition - eventually
            # partitioned backups will have an election, and then requests will
            # succeed again
            r = c.post("/app/log/private", {"id": key, "msg": val_b})
            assert r.status_code == http.HTTPStatus.GATEWAY_TIMEOUT, r

            network.wait_for_new_primary(primary, nodes=backups)

            # This may need a new client after https://github.com/microsoft/CCF/issues/3952
            r = c.get(f"/app/log/private?id={key}")
            assert r.status_code == http.HTTPStatus.OK, r
            assert r.body.json()["msg"] == val_a, r

    LOG.info("Drop partition and wait for reunification")
    network.wait_for_primary_unanimity()
    primary, backups = network.find_nodes()
    backup = backups[0]
    check_can_progress(primary)
    check_can_progress(backup)

    LOG.info("One-way partition may lead to misleading response")
    # Construct a partial partition, where the backup forwards but does not hear responses
    rules = network.partitioner.isolate_node(
        backup,
        isolation_dir=infra.partitions.IsolationDir.INBOUND_REQUESTS
        | infra.partitions.IsolationDir.OUTBOUND_RESPONSES,
    )
    with backup.client("user0") as c:
        # NB: Although this backup reports a timeout, the operation was actually
        # successfully forwarded!
        r = c.post("/app/log/private", {"id": key, "msg": val_b})
        assert r.status_code == http.HTTPStatus.GATEWAY_TIMEOUT, r

    with primary.client("user0") as c:
        r = c.get(f"/app/log/private?id={key}")
        assert r.status_code == http.HTTPStatus.OK, r
        assert r.body.json()["msg"] == val_b, r

    rules.drop()
    network.wait_for_primary_unanimity()


@reqs.description(
    "Session consistency is provided, and inconsistencies after elections are replaced by errors"
)
@reqs.supports_methods("/app/log/private")
@reqs.no_http2()
def test_session_consistency(network, args):
    # Ensure we have 5 nodes
    original_size = network.resize(5, args)

    primary, backups = network.find_nodes()
    backup = backups[0]

    with contextlib.ExitStack() as stack:
        client_primary_0 = stack.enter_context(
            primary.client("user0", description="primary 0")
        )
        client_primary_1 = stack.enter_context(
            primary.client("user0", description="primary 1")
        )
        client_backup_0 = stack.enter_context(
            backup.client("user0", description="backup 0")
        )
        client_backup_1 = stack.enter_context(
            backup.client("user0", description="backup 1")
        )

        # Create some new state
        msg_id = 42
        msg_a = "First write, to primary"
        r = client_primary_0.post(
            "/app/log/private",
            {
                "id": msg_id,
                "msg": msg_a,
            },
        )
        assert r.status_code == http.HTTPStatus.OK, r

        # Read this state on a second session
        r = client_primary_1.get(f"/app/log/private?id={msg_id}")
        assert r.status_code == http.HTTPStatus.OK, r
        assert r.body.json()["msg"] == msg_a, r

        # Wait for that to be committed on all backups
        network.wait_for_all_nodes_to_commit(primary)

        # Write on backup, resulting in a forwarded request
        # Confirm that this session can read that write, since it remains forwarded
        # Meanwhile another session to the same node may not see it
        # NB: The latter property is not possible to test systematically, as it
        # relies on a race - does the read on the second session happen before consensus
        # update's the backup's state. So we try in a loop
        n_attempts = 20
        for i in range(n_attempts):
            last_message = f"Second write, via backup ({i})"
            r = client_backup_0.post(
                "/app/log/private",
                {
                    "id": msg_id,
                    "msg": last_message,
                },
            )
            assert r.status_code == http.HTTPStatus.OK, r

            r = client_backup_1.get(f"/app/log/private?id={msg_id}")
            assert r.status_code == http.HTTPStatus.OK, r
            if r.body.json()["msg"] != last_message:
                LOG.info(
                    f"Successfully saw a different value on second session after {i} attempts"
                )
                break
        else:
            raise RuntimeError(
                f"Failed to observe evidence of session forwarding after {n_attempts} attempts"
            )

        @reqs.description("check_session_consistency")
        def check_session_consistency(sessions, should_error=False):
            for client in sessions:
                try:
                    r = client.get(f"/app/log/private?id={msg_id}")
                    assert r.status_code == http.HTTPStatus.OK, r
                    assert (
                        not should_error
                    ), f"Session {client.description} survived unexpectedly"
                except ConnectionResetError as e:
                    assert (
                        should_error
                    ), f"Session {client.description} was killed unexpectedly: {e}"

        # Partition primary and forwarding backup from other backups
        with network.partitioner.partition([primary, backup]):
            # Write on partitioned primary
            msg0 = "AA"
            r0 = client_primary_0.post(
                "/app/log/private",
                {
                    "id": msg_id,
                    "msg": msg0,
                },
            )
            assert r0.status_code == http.HTTPStatus.OK

            # Read from partitioned backup, over forwarded session to primary
            r1 = client_backup_0.get(f"/app/log/private?id={msg_id}")
            assert r1.status_code == http.HTTPStatus.OK

            # At this point despite partition these nodes believe this new transaction
            # is still valid, and will still report it, so there is no consistency error
            check_session_consistency(
                # NB: Only use these sessions, or we 'pollute' the other sessions
                # with recent TxIDs
                (client_primary_0, client_backup_0),
                False,
            )

            # Even once CheckQuorum takes effect and the primary stands down, they
            # know nothing contradictory so session consistency is maintained
            try:
                primary.wait_for_leadership_state(
                    r0.view, "Follower", timeout=2 * args.election_timeout_ms / 1000
                )
            except TimeoutError:
                # TODO: Shouldn't be happening
                LOG.error("Timed out, ignoring")
            check_session_consistency(
                (client_primary_0, client_backup_0),
                True,
            )

            # Ensure the majority partition have elected their own new primary
            try:
                _, new_view = network.wait_for_new_primary(primary, nodes=backups[1:])
            except TimeoutError:
                # TODO: Shouldn't be happening
                LOG.error("Timed out, ignoring")

        # TODO: Describe what we're seeing and expecting here
        network.wait_for_primary_unanimity(min_view=new_view - 1)

        check_session_consistency(
            (
                client_primary_0,
                client_primary_1,
                client_backup_0,
                client_backup_1,
            ),
            True,
        )

    # Restore original network size
    network.resize(original_size, args)

    return network


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

        # test_invalid_partitions(network, args)
        # test_partition_majority(network, args)
        # test_isolate_primary_from_one_backup(network, args)
        # test_new_joiner_helps_liveness(network, args)
        # for n in range(5):
        #     test_isolate_and_reconnect_primary(network, args, iteration=n)
        # test_election_reconfiguration(network, args)
        # test_forwarding_timeout(network, args)
        test_session_consistency(network, args)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--include-2tx-reconfig",
            help="Include tests for the 2-transaction reconfiguration scheme",
            default=False,
            action="store_true",
        )

    args = infra.e2e_args.cli_args(add)
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    args.package = "samples/apps/logging/liblogging"
    args.snapshot_tx_interval = 20

    run(args)
    # run_2tx_reconfig_tests(args)
