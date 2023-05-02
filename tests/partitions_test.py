# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import infra.network
import infra.net
import infra.interfaces
import infra.e2e_args
import infra.partitions
import infra.logging_app as app
import suite.test_requirements as reqs
from datetime import datetime, timedelta
from infra.checker import check_can_progress, check_does_not_progress
import pprint
from infra.tx_status import TxStatus
import time
import http
import contextlib
import ccf.ledger
from reconfiguration import test_ledger_invariants

from loguru import logger as LOG


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
            network.wait_for_new_primary(
                primary,
                timeout_multiplier=3,
            )
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
    initial_txid = network.txs.issue(network, send_private=False)

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

    new_primary = network.wait_for_primary_unanimity(min_view=initial_txid.view)
    assert new_primary == b_1

    new_view = network.txs.issue(network, send_private=False).view

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

        new_primary, _ = network.wait_for_new_primary(primary, nodes=backups)
        new_tx_resp = check_can_progress(new_primary)

        # CheckQuorum: the primary node should automatically step
        # down if it has not heard back from a majority of backups.
        # However, it is not guaranteed that the transient follower state
        # will be observed, so wait for candidate state instead.
        # The isolated primary will stay in follower state once Pre-Vote
        # is implemented. https://github.com/microsoft/CCF/issues/2577
        primary.wait_for_leadership_state(
            primary_view, ["Candidate"], timeout=2 * args.election_timeout_ms / 1000
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
    network.txs.issue(network, number_txs=10, send_private=False)

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
            r = c.post("/app/log/public", {"id": 42, "msg": "Hello world"})
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


@reqs.description("Test node-to-node channel behaviour once certs have expired")
@reqs.exactly_n_nodes(3)
def test_expired_certs(network, args):
    primary, (backup_a, backup_b) = network.find_nodes()

    def set_certs(from_days_diff, validity_period_days, nodes):
        valid_from = str(
            infra.crypto.datetime_to_X509time(
                datetime.utcnow() + timedelta(days=from_days_diff)
            )
        )
        for node in nodes:
            network.consortium.set_node_certificate_validity(
                primary,
                node,
                valid_from=valid_from,
                validity_period_days=validity_period_days,
            )
            node.set_certificate_validity_period(
                valid_from,
                validity_period_days,
            )
            # Wait for this node to receive this updated cert, and start advertising it
            timeout = 2
            end_time = time.time() + timeout
            while True:
                try:
                    node.verify_certificate_validity_period()
                    LOG.info("Successfully updated cert")
                    break
                except ValueError as ve:
                    LOG.warning(f"Cert is still old value: {ve}")
                    assert (
                        time.time() < end_time
                    ), f"Cert has not been updated after {timeout}s"
                    time.sleep(0.2)

    # Expired cert is only an issue on channel creation.
    # Force channel creation by partitioning to cause controlled election.
    with contextlib.ExitStack() as stack:
        # Partition backup_b from others
        with network.partitioner.partition([backup_b]):
            # Advance state, committed by presence on primary and backup_a
            with primary.client("user0") as c:
                r = c.post("/app/log/public", {"id": 42, "msg": "hello world"})
                assert r.status_code == http.HTTPStatus.OK, r
                c.wait_for_commit(r)

            # Expire the certs of primary and backup_a - these are the only viable
            # candidates due to the newly committed suffix
            # NB: Once we start doing this, speaking to these nodes is tricky, because
            # client auth will also fail => disable ca verification
            primary.verify_ca_by_default = False
            backup_a.verify_ca_by_default = False
            set_certs(
                from_days_diff=-30, validity_period_days=7, nodes=(primary, backup_a)
            )

            # Partition primary, so that backup_a is only viable candidate, and must try
            # to create channels to backup_b
            stack.enter_context(network.partitioner.partition([primary]))

        # Restore connectivity between backups and wait for election
        network.wait_for_primary_unanimity(nodes=[backup_a, backup_b], min_view=r.view)

        # Should now be able to make progress
        check_can_progress(backup_a)

    # Restore connectivity with primary, an election may or may not happen
    network.wait_for_primary_unanimity(min_view=r.view)

    # Set valid node certs so that future clients can speak to these nodes
    set_certs(from_days_diff=-1, validity_period_days=7, nodes=(primary, backup_a))

    # Can now speak to these again
    primary.verify_ca_by_default = True
    backup_a.verify_ca_by_default = True

    return network


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
        r = c.post("/app/log/public", {"id": key, "msg": val_a})
        assert r.status_code == http.HTTPStatus.OK

        network.wait_for_all_nodes_to_commit(primary=primary)

    LOG.info("Cross-partition write request is forwarded and times out")
    with network.partitioner.partition(backups):
        with backup.client("user0") as c:
            # NB: Only fails if request happens soon after partition - eventually
            # partitioned backups will have an election, and then requests will
            # succeed again
            r = c.post("/app/log/public", {"id": key, "msg": val_b})
            assert r.status_code == http.HTTPStatus.GATEWAY_TIMEOUT, r

            network.wait_for_new_primary(primary, nodes=backups)

        with backup.client("user0") as c:
            r = c.get(f"/app/log/public?id={key}")
            assert r.status_code == http.HTTPStatus.OK, r
            assert r.body.json()["msg"] == val_a, r

    LOG.info("Drop partition and wait for reunification")
    network.wait_for_primary_unanimity()
    primary, backups = network.find_nodes()
    with primary.client() as c:
        view = c.get("/node/network").body.json()["current_view"]

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
        r = c.post("/app/log/public", {"id": key, "msg": val_b})
        assert r.status_code == http.HTTPStatus.GATEWAY_TIMEOUT, r

    with primary.client("user0") as c:
        r = c.get(f"/app/log/public?id={key}")
        assert r.status_code == http.HTTPStatus.OK, r
        assert r.body.json()["msg"] == val_b, r

    # Wait for new view on isolated backup so that network is left
    # in a stable state when partition is lifted
    backup.wait_for_leadership_state(
        min_view=view,
        leadership_states=["Candidate"],
        timeout=4 * args.election_timeout_ms / 1000,
    )
    rules.drop()

    network.wait_for_primary_unanimity(min_view=view)


@reqs.description(
    "Session consistency is provided, and inconsistencies after elections are replaced by errors"
)
@reqs.supports_methods("/app/log/public")
@reqs.no_http2()
def test_session_consistency(network, args):
    # Ensure we have 5 nodes
    original_size = network.resize(5, args)

    primary, backups = network.find_nodes()
    backup = backups[0]

    with contextlib.ExitStack() as stack:
        client_primary_A = stack.enter_context(
            primary.client(
                "user0",
                description_suffix="A",
                impl_type=infra.clients.RawSocketClient,
            )
        )
        client_primary_B = stack.enter_context(
            primary.client(
                "user0",
                description_suffix="B",
                impl_type=infra.clients.RawSocketClient,
            )
        )
        client_backup_C = stack.enter_context(
            backup.client(
                "user0",
                description_suffix="C",
                impl_type=infra.clients.RawSocketClient,
            )
        )
        client_backup_D = stack.enter_context(
            backup.client(
                "user0",
                description_suffix="D",
                impl_type=infra.clients.RawSocketClient,
            )
        )

        # Create some new state
        msg_id = 42
        msg_a = "First write, to primary"
        r = client_primary_A.post(
            "/app/log/public",
            {
                "id": msg_id,
                "msg": msg_a,
            },
        )
        assert r.status_code == http.HTTPStatus.OK, r

        # Read this state on a second session
        r = client_primary_B.get(f"/app/log/public?id={msg_id}")
        assert r.status_code == http.HTTPStatus.OK, r
        assert r.body.json()["msg"] == msg_a, r

        # Wait for that to be committed on all backups
        network.wait_for_all_nodes_to_commit(primary)

        # Write on backup, resulting in a forwarded request.
        # Confirm that this session can read that write, since it remains forwarded.
        # Meanwhile a separate session to the same backup node may not see it.
        # NB: The latter property is not possible to test systematically, as it
        # relies on a race - does the read on the second session happen before consensus
        # update's the backup's state. Solution is to try in a loop, with a high probability
        # that we observe the desired ordering after just a few iterations.
        n_attempts = 20
        for i in range(n_attempts):
            last_message = f"Second write, via backup ({i})"
            r = client_backup_C.post(
                "/app/log/public",
                {
                    "id": msg_id,
                    "msg": last_message,
                },
            )
            # Note: No assert on response status code code here as forwarded response
            # may be dropped by primary node in debug builds (https://github.com/microsoft/CCF/issues/4625)

            r = client_backup_D.get(f"/app/log/public?id={msg_id}")
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

        def check_sessions_alive(sessions):
            for client in sessions:
                try:
                    r = client.get(f"/app/log/public?id={msg_id}")
                    assert r.status_code == http.HTTPStatus.OK, r
                except ConnectionResetError as e:
                    raise AssertionError(
                        f"Session {client.description} was killed unexpectedly: {e}"
                    ) from e

        def check_sessions_dead(
            sessions,
        ):
            for client in sessions:
                try:
                    r = client.get(f"/app/log/public?id={msg_id}")
                    assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r
                    assert r.body.json()["error"]["code"] == "SessionConsistencyLost", r
                except ConnectionResetError as e:
                    raise AssertionError(
                        f"Session {client.description} was killed without first returning an error: {e}"
                    ) from e

                # After returning error, session should be terminated, so all subsequent requests should fail
                try:
                    client.get("/node/commit")
                    raise AssertionError(
                        f"Session {client.description} survived unexpectedly"
                    )
                except ConnectionResetError:
                    LOG.info(f"Session {client.description} was terminated as expected")

        def wait_for_new_view(node, original_view, timeout_multiplier):
            election_s = args.election_timeout_ms / 1000
            timeout = election_s * timeout_multiplier
            end_time = time.time() + timeout
            while time.time() < end_time:
                with node.client() as c:
                    r = c.get("/node/network")
                    assert r.status_code == http.HTTPStatus.OK, r
                    if r.body.json()["current_view"] > original_view:
                        return
                time.sleep(0.1)
            raise TimeoutError(
                f"Node failed to reach view higher than {original_view} after waiting {timeout}s"
            )

        # Partition primary and forwarding backup from other backups
        with network.partitioner.partition([primary, backup]):
            # Write on partitioned primary
            msg0 = "Hello world"
            r0 = client_primary_A.post(
                "/app/log/public",
                {
                    "id": msg_id,
                    "msg": msg0,
                },
            )
            assert r0.status_code == http.HTTPStatus.OK

            # Read from partitioned backup, over forwarded session to primary
            r1 = client_backup_C.get(f"/app/log/public?id={msg_id}")
            assert r1.status_code == http.HTTPStatus.OK
            assert r1.body.json()["msg"] == msg0, r1

            # Despite partition, these sessions remain live
            check_sessions_alive((client_primary_A, client_backup_C))

            # Once CheckQuorum takes effect and the primary stands down, all sessions
            # on the primary report a risk of inconsistency
            wait_for_new_view(backup, r0.view, 4)
            check_sessions_dead(
                (
                    # This session wrote state which is now at risk of being lost
                    client_primary_A,
                    # This session only read old state which is still valid
                    client_primary_B,
                    # This is also immediately true for forwarded sessions on the backup
                    client_backup_C,
                )
            )

            # The backup may not have received any view increment yet, so a non-forwarded
            # session on the backup may still be valid. This is a temporary, racey situation,
            # and safe (the backup has not rolled back, and is still reporting state in the
            # old session).
            # Test that once the view has advanced, that backup session is also terminated.
            wait_for_new_view(backup, r0.view, 1)
            check_sessions_dead((client_backup_D,))

    # Wait for network stability after healing partition
    network.wait_for_primary_unanimity(min_view=r0.view)

    # Restore original network size
    network.resize(original_size, args)

    return network


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
        test_expired_certs(network, args)
        for n in range(5):
            test_isolate_and_reconnect_primary(network, args, iteration=n)
        test_election_reconfiguration(network, args)
        test_forwarding_timeout(network, args)
        test_session_consistency(network, args)

        test_ledger_invariants(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    args.package = "samples/apps/logging/liblogging"
    args.snapshot_tx_interval = (
        20  # Increase snapshot frequency for faster reconfigurations
    )

    run(args)
