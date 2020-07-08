# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.proc
import infra.notification
import infra.net
import infra.e2e_args
import infra.suspension as suspend
import random
import infra.logging_app as app

from loguru import logger as LOG

# pbft will store up to 34 of each message type (pre-prepare/prepare/commit) and retransmit these messages to replicas that are behind, enabling catch up.
# If a replica is too far behind then we need to send entries from the ledger, which is one of the things we want to test here.
# By sending 18 RPC requests and a commit rpc for each of them (what raft considers as a read pbft will process as a write),
# we are sure that we will have to go via the ledger to help late joiners catch up (total 36 reqs > 34)
TOTAL_REQUESTS = 9  # x2 is 18 since LoggingTxs app sends a private and a public request for each tx index


def run(args):
    hosts = ["localhost", "localhost", "localhost"]

    LOG.info(f"setting seed to {args.seed}")
    random.seed(args.seed)
    txs = app.LoggingTxs()

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb, txs=txs
    ) as network:
        network.start_and_join(args)
        original_nodes = network.get_joined_nodes()
        view_info = {}

        suspend.update_view_info(network, view_info)
        app.test_run_txs(network=network, args=args, num_txs=TOTAL_REQUESTS)
        suspend.update_view_info(network, view_info)

        nodes_to_kill = [network.find_any_backup()]
        nodes_to_keep = [n for n in original_nodes if n not in nodes_to_kill]

        # check that a new node can catch up after all the requests
        late_joiner = network.create_and_trust_node(args.package, "localhost", args)
        nodes_to_keep.append(late_joiner)

        # some requests to be processed while the late joiner catches up
        # (no strict checking that these requests are actually being processed simultaneously with the node catchup)
        app.test_run_txs(
            network=network,
            args=args,
            num_txs=int(TOTAL_REQUESTS / 2),
            nodes=original_nodes,  # doesn't contain late joiner
            verify=False,  # will try to verify for late joiner and it might not be ready yet
        )

        suspend.wait_for_late_joiner(original_nodes[0], late_joiner)

        # kill the old node(s) and ensure we are still making progress
        for backup_to_retire in nodes_to_kill:
            LOG.success(f"Stopping node {backup_to_retire.node_id}")
            backup_to_retire.stop()

        # check nodes are ok after we killed one off
        app.test_run_txs(
            network=network,
            args=args,
            nodes=nodes_to_keep,
            num_txs=len(nodes_to_keep),
            timeout=30,
            ignore_failures=True,
            # in the event of an early view change due to the late joiner this might
            # take longer than usual to complete and we don't want the test to break here
        )

        suspend.test_suspend_nodes(network, args, nodes_to_keep)

        # run txs while nodes get suspended
        app.test_run_txs(
            network=network,
            args=args,
            num_txs=4 * TOTAL_REQUESTS,
            timeout=30,
            ignore_failures=True,
            # in the event of an early view change due to the late joiner this might
            # take longer than usual to complete and we don't want the test to break here
        )

        suspend.update_view_info(network, view_info)

        # check nodes have resumed normal execution before shutting down
        app.test_run_txs(network=network, args=args, num_txs=len(nodes_to_keep))

        # we have asserted that all nodes are caught up
        # assert that view changes actually did occur
        assert len(view_info) > 1

        LOG.success("----------- views and primaries recorded -----------")
        for view, primary in view_info.items():
            LOG.success(f"view {view} - primary {primary}")


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--seed",
            help="seed used to randomise the node suspension timeouts",
            default=42,
        )

    args = infra.e2e_args.cli_args(add)
    if args.js_app_script:
        args.package = "libjs_generic"
    elif args.app_script:
        args.package = "liblua_generic"
    else:
        args.package = "liblogging"
    run(args)
