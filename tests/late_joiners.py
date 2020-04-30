# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import time
import infra.ccf
import infra.proc
import infra.notification
import infra.net
import infra.e2e_args
from threading import Timer
import random
import contextlib
import suite.test_requirements as reqs
import infra.logging_app as app
import requests

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


@reqs.description("Find current primary")
def find_primary(network, args, term_info):
    try:
        cur_primary, cur_term = network.find_primary()
        term_info[cur_term] = cur_primary.node_id
    except TimeoutError:
        LOG.info("Trying to access a suspended network")
    return network


@reqs.description("Running transactions against logging app")
@reqs.supports_methods("LOG_record", "LOG_record_pub", "LOG_get", "LOG_get_pub")
@reqs.at_least_n_nodes(3)
def run_txs_on(
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
        timeout=30,
        wait_for_sync=wait_for_sync,
    )
    if nodes is None:
        nodes = network.get_joined_nodes()
    num_nodes = len(nodes)
    txs_per_node = max(1, int(num_txs / num_nodes))

    for node in nodes:
        txs.issue_on_node(
            network=network,
            remote_node=node,
            number_txs=txs_per_node,
            consensus=args.consensus,
        )

    if verify:
        txs.verify_last_tx(network)
    else:
        LOG.warning("Skipping log messages verification")

    return network


@reqs.description("Adding a very late joiner")
def add_late_joiner(network, args, nodes_to_keep):
    new_node = network.create_and_trust_node(args.package, "localhost", args)
    nodes_to_keep.append(new_node)
    return network


def run(args):
    hosts = ["localhost", "localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        first_node, _ = network.find_nodes()
        all_nodes = network.get_joined_nodes()
        term_info = {}
        find_primary(network, args, term_info)

        election_timeout = (
            args.pbft_view_change_timeout / 1000
            if args.consensus == "pbft"
            else args.raft_election_timeout / 1000
        )

        run_txs_on(network=network, args=args, num_txs=TOTAL_REQUESTS)
        find_primary(network, args, term_info)

        nodes_to_kill = [network.find_any_backup()]
        nodes_to_keep = [n for n in all_nodes if n not in nodes_to_kill]

        # check that a new node can catch up after all the requests
        add_late_joiner(network, args, nodes_to_keep)
        late_joiner = nodes_to_keep[-1]

        # some requests to be processed while the late joiner catches up
        # (no strict checking that these requests are actually being processed simultaneously with the node catchup)
        run_txs_on(
            network=network,
            args=args,
            num_txs=int(TOTAL_REQUESTS / 2),
            start_idx=1000,
            timeout=30,
            can_fail=True,
            wait_for_sync=True,
        )

        if not args.skip_suspension:
            # kill the old node(s) and ensure we are still making progress with the new one(s)
            for node in nodes_to_kill:
                LOG.info(f"Stopping node {node.node_id}")
                node.stop()

            # check nodes are ok after we killed one off
            run_txs_on(network=network, args=args, nodes=nodes_to_keep, start_idx=2000)

            find_primary(network, args, term_info)
            cur_term = max(term_info.keys())
            cur_primary_id = term_info[cur_term]

            # first timer determines after how many seconds each node will be suspended
            timeouts = []
            suspended_nodes = []
            for i, node in enumerate(nodes_to_keep):
                # if pbft suspend half of them including the primary
                if i % 2 != 0 and args.consensus == "pbft":
                    continue
                LOG.success(f"Will suspend node with id {node.node_id}")
                t = random.uniform(0, 2)
                LOG.info(f"Initial timer for node {node.node_id} is {t} seconds...")
                timeouts.append((t, node))
                suspended_nodes.append(node.node_id)

            for t, node in timeouts:
                suspend_time = election_timeout
                if node.node_id == cur_primary_id and args.consensus == "pbft":
                    # if pbft suspend the primary for more than twice the election timeout
                    # in order to make sure view changes will be triggered
                    suspend_time = 2.5 * suspend_time
                tm = Timer(t, timeout_handler, args=[node, True, suspend_time])
                tm.start()

            # run txs while nodes get suspended
            run_txs_on(
                network=network,
                args=args,
                nodes=nodes_to_keep,
                num_txs=4 * TOTAL_REQUESTS,
                start_idx=3000,
                can_fail=True,
            )
            find_primary(network, args, term_info)

            # check nodes have resumed normal execution before shutting down
            run_txs_on(network=network, args=args, nodes=nodes_to_keep, start_idx=4000)

            # we have asserted that all nodes are caught up
            # assert that view changes actually did occur
            assert len(term_info) > 1

            LOG.success("----------- terms and primaries recorded -----------")
            for term, primary in term_info.items():
                LOG.success(f"term {term} - primary {primary}")


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--skip-suspension",
            help="Don't suspend any nodes (i.e. just do late join)",
            action="store_true",
        )

    args = infra.e2e_args.cli_args(add)
    if args.js_app_script:
        args.package = "libjs_generic"
    elif args.app_script:
        args.package = "liblua_generic"
    else:
        args.package = "liblogging"
    run(args)
