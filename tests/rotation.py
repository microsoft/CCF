# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import suite.test_requirements as reqs
import reconfiguration
from infra.checker import check_can_progress

from loguru import logger as LOG


@reqs.description("Replace all nodes in a single transaction")
@reqs.at_least_n_nodes(3)
def test_replace_all_nodes(network, args):
    current_nodes = network.get_joined_nodes()
    current_node_ids = [node.node_id for node in current_nodes]

    def make_node():
        node = network.create_node("local://localhost")
        network.join_node(node, args.package, args, timeout=3, from_snapshot=False)
        return node

    new_nodes = [make_node() for _ in range(len(current_nodes))]
    new_node_ids = [node.node_id for node in new_nodes]

    trust_new_nodes = [
        {"name": "transition_node_to_trusted", "args": {"node_id": node_id}}
        for node_id in new_node_ids
    ]
    remove_old_nodes = [
        {"name": "remove_node", "args": {"node_id": node_id}}
        for node_id in current_node_ids
    ]
    replace_nodes = {"actions": trust_new_nodes + remove_old_nodes}

    primary, _ = network.find_primary()
    proposal = network.consortium.get_any_active_member().propose(
        primary, replace_nodes
    )
    network.consortium.vote_using_majority(
        primary,
        proposal,
        {"ballot": "export function vote (proposal, proposer_id) { return true }"},
        wait_for_global_commit=False,
    )

    for node in new_nodes:
        LOG.info("Waiting for node {} to join", node.local_node_id)
        node.wait_for_node_to_join(timeout=10)

    new_primary, _ = network.wait_for_new_primary_in(new_node_ids, timeout_multiplier=3)
    check_can_progress(new_primary)

    for node in current_nodes:
        node.stop()
        network.nodes.remove(node)

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        # Replace all nodes repeatedly and check the network still operates
        if args.consensus != "bft":
            LOG.info(f"Replacing all nodes {args.rotation_replacements} times")
            for i in range(args.rotation_replacements):
                LOG.warning(f"Replacement {i}")
                test_replace_all_nodes(network, args)

        # Replace primary repeatedly and check the network still operates
        if args.consensus != "bft":
            LOG.info(f"Retiring primary {args.rotation_retirements} times")
            for i in range(args.rotation_retirements):
                LOG.warning(f"Retirement {i}")
                reconfiguration.test_add_node(network, args)
                reconfiguration.test_retire_primary(network, args)

        if args.consensus == "bft":
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
            "--rotation-replacements",
            help="Number of times to replace all nodes",
            type=int,
            default=3,
        )

    args = infra.e2e_args.cli_args(add=add)
    args.package = "liblogging"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    args.initial_member_count = 1
    run(args)
