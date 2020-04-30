# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.ccf
import infra.proc
import infra.notification
import infra.net
import infra.e2e_args
from threading import Timer
import random
import suite.test_requirements as reqs
import infra.logging_app as app

from loguru import logger as LOG

# pbft will store up to 34 of each message type (pre-prepare/prepare/commit) and retransmit these messages to replicas that are behind, enabling catch up.
# If a replica is too far behind then we need to send entries from the ledger, which is one of the things we want to test here.
# By sending 18 RPC requests and a getCommit for each of them (what raft consideres as a read pbft will process as a write),
# we are sure that we will have to go via the ledger to help late joiners catch up (total 36 reqs > 34)
TOTAL_REQUESTS = 9  # x2 is 18 since LoggingTxs app sends a private and a public request for each tx index

s = random.randint(1, 10)
LOG.info(f"setting seed to {s}")
random.seed(s)


def timeout_handler(node, suspend, election_timeout):
    if suspend:
        # We want to suspend the nodes' process so we need to initiate a new timer to wake it up eventually
        node.suspend()
        next_timeout = random.uniform(2 * election_timeout, 3 * election_timeout)
        LOG.info(f"New timer set for node {node.node_id} is {next_timeout} seconds")
        t = Timer(next_timeout, timeout_handler, args=[node, False, 0])
        t.start()
    else:
        node.resume()


def update_term_info(network, term_info):
    try:
        cur_primary, cur_term = network.find_primary()
        term_info[cur_term] = cur_primary.node_id
    except TimeoutError:
        LOG.info("Trying to access a suspended network")


@reqs.description("Running transactions against logging app")
@reqs.supports_methods("LOG_record", "LOG_record_pub", "LOG_get", "LOG_get_pub")
@reqs.at_least_n_nodes(3)
def test_run_txs(
    network,
    args,
    nodes=None,
    num_txs=1,
    start_idx=0,
    timeout=3,
    can_fail=False,
    notifications_queue=None,
    verify=True,
    wait_for_sync=False,
):
    txs = app.LoggingTxs(
        notifications_queue=notifications_queue,
        tx_index_start=start_idx,
        can_fail=can_fail,
        timeout=timeout,
        wait_for_sync=wait_for_sync,
    )
    if nodes is None:
        nodes = network.get_joined_nodes()
    num_nodes = len(nodes)

    for tx in range(num_txs):
        txs.issue_on_node(
            network=network,
            remote_node=nodes[tx % num_nodes],
            number_txs=1,
            consensus=args.consensus,
        )

    if verify:
        txs.verify_last_tx(network)
    else:
        LOG.warning("Skipping log messages verification")

    return network


@reqs.description("Adding a very late joiner")
def test_add_late_joiner(network, args, nodes_to_keep):
    new_node = network.create_and_trust_node(args.package, "localhost", args)
    nodes_to_keep.append(new_node)
    return network


@reqs.description("Suspend nodes")
@reqs.at_least_n_nodes(3)
def test_suspend_nodes(network, args, nodes_to_keep):
    cur_primary, _ = network.find_primary()

    # first timer determines after how many seconds each node will be suspended
    timeouts = []
    for i, node in enumerate(nodes_to_keep):
        # if pbft suspend half of them including the primary
        if i % 2 != 0 and args.consensus == "pbft":
            continue
        LOG.success(f"Will suspend node with id {node.node_id}")
        t = random.uniform(0, 2)
        LOG.info(f"Initial timer for node {node.node_id} is {t} seconds...")
        timeouts.append((t, node))

    for t, node in timeouts:
        suspend_time = (
            args.pbft_view_change_timeout / 1000
            if args.consensus == "pbft"
            else args.raft_election_timeout / 1000
        )
        if node.node_id == cur_primary.node_id and args.consensus == "pbft":
            # if pbft suspend the primary for more than twice the election timeout
            # in order to make sure view changes will be triggered
            suspend_time = 2.5 * suspend_time
        tm = Timer(t, timeout_handler, args=[node, True, suspend_time])
        tm.start()
    return network


@reqs.description("Retiring backup(s)")
def test_retire_nodes(network, args, nodes_to_kill):
    primary, _ = network.find_primary()
    for backup_to_retire in nodes_to_kill:
        LOG.success(f"Stopping node {backup_to_retire.node_id}")
        network.consortium.retire_node(primary, backup_to_retire)
        backup_to_retire.stop()
    return network


def run(args):
    hosts = ["localhost", "localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        all_nodes = network.get_joined_nodes()
        term_info = {}
        update_term_info(network, term_info)

        test_run_txs(network=network, args=args, num_txs=TOTAL_REQUESTS)
        update_term_info(network, term_info)

        nodes_to_kill = [network.find_any_backup()]
        nodes_to_keep = [n for n in all_nodes if n not in nodes_to_kill]

        # check that a new node can catch up after all the requests
        test_add_late_joiner(network, args, nodes_to_keep)

        # some requests to be processed while the late joiner catches up
        # (no strict checking that these requests are actually being processed simultaneously with the node catchup)
        test_run_txs(
            network=network,
            args=args,
            num_txs=int(TOTAL_REQUESTS / 2),
            start_idx=1000,
            timeout=30,
            can_fail=True,
            wait_for_sync=True,
        )

        # kill the old node(s) and ensure we are still making progress with the new one(s)
        test_retire_nodes(network, args, nodes_to_kill)

        # check nodes are ok after we killed one off
        test_run_txs(
            network=network,
            args=args,
            nodes=nodes_to_keep,
            num_txs=len(nodes_to_keep),
            start_idx=2000,
        )

        test_suspend_nodes(network, args, nodes_to_keep)

        # run txs while nodes get suspended
        test_run_txs(
            network=network,
            args=args,
            nodes=nodes_to_keep,
            num_txs=4 * TOTAL_REQUESTS,
            start_idx=3000,
            can_fail=True,
        )

        update_term_info(network, term_info)

        # check nodes have resumed normal execution before shutting down
        test_run_txs(
            network=network,
            args=args,
            nodes=nodes_to_keep,
            num_txs=len(nodes_to_keep),
            start_idx=4000,
        )

        # we have asserted that all nodes are caught up
        # assert that view changes actually did occur
        assert len(term_info) > 1

        LOG.success("----------- terms and primaries recorded -----------")
        for term, primary in term_info.items():
            LOG.success(f"term {term} - primary {primary}")


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    if args.js_app_script:
        args.package = "libjs_generic"
    elif args.app_script:
        args.package = "liblua_generic"
    else:
        args.package = "liblogging"
    run(args)
