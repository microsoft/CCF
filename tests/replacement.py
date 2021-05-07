# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import reconfiguration
import suite.test_requirements as reqs

from loguru import logger as LOG


@reqs.description("Replace a node on the same addresses")
@reqs.at_least_n_nodes(3)  # Should be at_least_f_failures(1)
def test_node_replacement(network, args):
    primary, backups = network.find_nodes()

    nodes = network.get_joined_nodes()
    node_to_replace = backups[-1]
    f = infra.e2e_args.max_f(args, len(nodes))
    f_backups = backups[:f]

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
    LOG.info(
        f"Stopping {len(f_backups)} other nodes to make progress depend on the replacement"
    )
    for other_backup in f_backups:
        other_backup.stop()
    # Confirm the network can make progress
    reconfiguration.check_can_progress(primary)


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        test_node_replacement(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    args.initial_member_count = 1
    run(args)
