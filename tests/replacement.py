# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import suite.test_requirements as reqs
import reconfiguration

from loguru import logger as LOG

def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, _ = network.find_primary()

        node_to_replace = network.get_joined_nodes()[-1]
        other_backup = network.get_joined_nodes()[-2]

        # Retire one node
        network.consortium.retire_node(primary, node_to_replace)
        node_to_replace.stop()
        reconfiguration.check_can_progress(primary)

        # Add in a node using the same address
        replacement_node = network.create_and_trust_node(
            args.package,
            f"local://{node_to_replace.host}:{node_to_replace.rpc_port}",
            args,
            node_port=node_to_replace.node_port,
            from_snapshot=False,
        )

        assert replacement_node.node_id != node_to_replace.node_id
        assert replacement_node.host == node_to_replace.host
        assert replacement_node.node_port == node_to_replace.node_port
        assert replacement_node.rpc_port == node_to_replace.rpc_port
        # Stop the other backup, to reach f=1. Network can only make progress
        # if new joiner is participating successfully
        other_backup.stop()
        # Confirm the network can make progress
        reconfiguration.check_can_progress(primary)

if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    args.nodes = ["local://localhost"] * 3
    args.initial_member_count = 1
    run(args)
