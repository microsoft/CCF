# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import suite.test_requirements as reqs
import reconfiguration
import time
from infra.checker import check_can_progress
from ccf.clients import CCFConnectionException

from loguru import logger as LOG


@reqs.description("Replace all nodes in a single transaction")
@reqs.at_least_n_nodes(3)
def test_replace_all_nodes(network, args):
    current_nodes = network.get_joined_nodes()
    current_node_ids = [node.node_id for node in current_nodes]

    def make_node():
        node = network.create_node("local://localhost")
        network.join_node(node, args.package, args, timeout=3)
        return node

    new_nodes = [make_node(), make_node(), make_node()]
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
        timeout=10,
    )

    for node in new_nodes:
        LOG.info("Waiting for node {} to join", node.local_node_id)
        node.wait_for_node_to_join(timeout=10)

    new_primary, _ = network.wait_for_new_primary_in(new_node_ids)
    check_can_progress(new_primary)

    for node in current_nodes:
        node.stop()
        network.nodes.remove(node)

    return network


@reqs.description("Suspend and resume primary")
@reqs.can_kill_n_nodes(1)
def test_suspend_primary(network, args):
    primary, backup = network.find_primary_and_any_backup()
    primary.suspend()
    if args.consensus == "bft":
        try:
            for _ in range(3):
                with backup.client("user0") as c:
                    _ = c.post(
                        "/app/log/private",
                        {
                            "id": -1,
                            "msg": "This is submitted to force a view change",
                        },
                    )
                time.sleep(5)
                backup = network.find_any_backup()
        except CCFConnectionException:
            LOG.warning(f"Could not successfully connect to node {backup.node_id}.")
    new_primary, _ = network.wait_for_new_primary(primary)
    check_can_progress(new_primary)
    primary.resume()
    check_can_progress(new_primary)
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

        return

        # Replace primary repeatedly and check the network still operates
        if args.consensus != "bft":
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
        parser.add_argument(
            "--rotation-replacements",
            help="Number of times to replace all nodes",
            type=int,
            default=3,
        )

    args = infra.e2e_args.cli_args(add=add)
    args.package = "liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.initial_member_count = 1
    run(args)
