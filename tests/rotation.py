# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import suite.test_requirements as reqs
import reconfiguration
from infra.checker import check_can_progress

from loguru import logger as LOG
import pprint


@reqs.description("Suspend and resume primary")
@reqs.at_least_n_nodes(3)
def test_suspend_primary(network, args):
    primary, _ = network.find_primary()
    primary.suspend()
    new_primary, _ = network.wait_for_new_primary(primary)
    check_can_progress(new_primary)
    primary.resume()
    check_can_progress(new_primary)
    return network

def show_configs(network):
    primary, _ = network.find_primary()
    with primary.client() as c:
        r = c.get("/node/consensus")
        pprint.pprint(r.body.json())

def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        # Replace primary repeatedly and check the network still operates
        LOG.info(f"Retiring primary {args.rotation_retirements} times")
        for i in range(args.rotation_retirements):
            LOG.warning(f"Retirement {i}")
            show_configs(network)
            reconfiguration.test_add_node(network, args)
            show_configs(network)
            reconfiguration.test_retire_primary(network, args)
            show_configs(network)

        return

        reconfiguration.test_add_node(network, args)
        # Suspend primary repeatedly and check the network still operates
        LOG.info(f"Suspending primary {args.rotation_suspensions} times")
        for i in range(args.rotation_suspensions):
            LOG.warning(f"Suspension {i}")
            test_suspend_primary(network, args)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "--rotation-retirements",
            help="Number of times to retired the primary",
            type=int,
            default=3,
        )
        parser.add_argument(
            "--rotation-suspensions",
            help="Number of times to suspend the primary",
            type=int,
            default=3,
        )

    args = infra.e2e_args.cli_args(add=add)
    args.package = "liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.initial_member_count = 1
    run(args)
