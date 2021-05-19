# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import suite.test_requirements as reqs
import reconfiguration
import pprint
from infra.checker import check_can_progress

from loguru import logger as LOG


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


@reqs.description("Replace all nodes in a single transaction")
@reqs.at_least_n_nodes(3)
def test_replace_all_nodes(network, args):
    current_nodes = network.get_joined_nodes()
    current_node_ids = [node.node_id for node in current_nodes]
    new_nodes = [network.create_and_add_pending_node(args.package, "local://localhost", args) for _ in range(3)]
    new_node_ids = [node.node_id for node in new_nodes]
    trust_new_nodes = [{"name": "transition_node_to_trusted", "args": {"node_id": node_id}} for node_id in new_node_ids]
    remove_old_nodes = [{"name": "remove_node", "args": {"node_id": node_id}} for node_id in current_node_ids]
    replace_nodes = {"actions": trust_new_nodes + remove_old_nodes}

    pprint.pprint(replace_nodes)

    primary, _ = network.find_primary()
    proposal = network.consortium.get_any_active_member().propose(primary, replace_nodes)
    network.consortium.vote_using_majority(primary, proposal, {"ballot": "export function vote (proposal, proposer_id) { return true }"}, timeout=10)

    new_primary, _ = network.wait_for_new_primary(primary)
    check_can_progress(new_primary)

    for node in current_nodes:
        network.nodes.remove(node)

def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        test_replace_all_nodes(network, args)
        return

        # Replace primary repeatedly and check the network still operates
        LOG.info(f"Retiring primary {args.rotation_retirements} times")
        for i in range(args.rotation_retirements):
            LOG.warning(f"Retirement {i}")
            reconfiguration.test_add_node(network, args)
            reconfiguration.test_retire_primary(network, args)

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
