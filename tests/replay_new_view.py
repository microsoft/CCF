# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.proc
import infra.net
import infra.e2e_args
import infra.suspension as suspend
import random
import infra.logging_app as app

from loguru import logger as LOG

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
        suspend.test_suspend_nodes(network, args)

        # run txs while nodes get suspended
        app.test_run_txs(
            network=network,
            args=args,
            num_txs=4 * TOTAL_REQUESTS,
            ignore_failures=True,
        )
        suspend.update_view_info(network, view_info)
        late_joiner = network.create_and_trust_node(args.package, "localhost", args)

        # some requests to be processed while the late joiner catches up
        # (no strict checking that these requests are actually being processed simultaneously with the node catchup)
        app.test_run_txs(
            network=network,
            args=args,
            num_txs=int(TOTAL_REQUESTS / 2),
            nodes=original_nodes,  # doesn't contain late joiner
            verify=False,  # will try to verify for late joiner and it might not be ready yet
        )

        caught_up = suspend.wait_for_late_joiner(original_nodes[0], late_joiner)
        if caught_up == suspend.LateJoinerStatus.Stuck:
            # should be removed when node configuration has been implemented to allow
            # a late joiner to force a view change
            LOG.warning("late joiner is stuck, stop trying if catchup fails again")
            suspend.wait_for_late_joiner(original_nodes[0], late_joiner, True)
        elif caught_up == suspend.LateJoinerStatus.NotReady:
            while caught_up == suspend.LateJoinerStatus.NotReady:
                LOG.warning("late joiner is not ready to accept RPC's yet")
                caught_up = suspend.wait_for_late_joiner(original_nodes[0], late_joiner)
        elif caught_up == suspend.LateJoinerStatus.Ready:
            LOG.success("late joiner caught up successfully")

        # check nodes have resumed normal execution before shutting down
        app.test_run_txs(
            network=network,
            args=args,
            num_txs=len(network.get_joined_nodes()),
            timeout=30,
            ignore_failures=True,
        )

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
