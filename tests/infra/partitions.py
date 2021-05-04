# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.node
import infra.network
import iptc
import atexit
from typing import List

from loguru import logger as LOG


CCF_IPTABLES_CHAIN = "CCF-TEST"

CCF_INPUT_RULE = {
    "protocol": "tcp",
    "target": CCF_IPTABLES_CHAIN,
    "tcp": {},
}


class Partitioner:
    @staticmethod
    def cleanup():
        if iptc.easy.has_chain("filter", CCF_IPTABLES_CHAIN):
            iptc.easy.flush_chain("filter", CCF_IPTABLES_CHAIN)
            iptc.easy.delete_rule("filter", "INPUT", CCF_INPUT_RULE)
            iptc.easy.delete_chain("filter", CCF_IPTABLES_CHAIN)
        LOG.success(f"Successfully cleanup chain {CCF_IPTABLES_CHAIN}")

    def __init__(self):
        # Create iptables chain
        if not iptc.easy.has_chain("filter", CCF_IPTABLES_CHAIN):
            iptc.easy.add_chain("filter", CCF_IPTABLES_CHAIN)

        # TODO: Check it hasn't got the rule already
        if not iptc.easy.has_rule("filter", "INPUT", CCF_INPUT_RULE):
            iptc.easy.insert_rule("filter", "INPUT", CCF_INPUT_RULE)

        # TODO:
        # Handle normal process termination + signals
        # atexit.register(Partitioner.cleanup)

    def __del__(self):
        Partitioner.cleanup()

    def isolate_node(self, node: infra.node.Node):
        base_rule = {"protocol": "tcp", "target": "DROP"}

        # TODO: Full duplex?

        # Isolates node server socket
        server_rule = {
            **base_rule,
            "dst": str(node.host),
            "tcp": {"dport": str(node.node_port)},
        }

        # Isolates all node client sockets
        client_rule = {
            **base_rule,
            "src": str(node.node_client_host),
        }

        LOG.info(f"Isolating node {node.host}:{node.node_port}")

        if iptc.easy.has_rule("filter", CCF_IPTABLES_CHAIN, server_rule):
            iptc.easy.delete_rule("filter", CCF_IPTABLES_CHAIN, server_rule)

        if iptc.easy.has_rule("filter", CCF_IPTABLES_CHAIN, client_rule):
            iptc.easy.delete_rule("filter", CCF_IPTABLES_CHAIN, client_rule)

        iptc.easy.insert_rule("filter", CCF_IPTABLES_CHAIN, server_rule)
        iptc.easy.insert_rule("filter", CCF_IPTABLES_CHAIN, client_rule)

    def isolate_node_from_other(self, node, other):
        LOG.info(f"Isolating node {node.local_node_id} from {other.local_node_id}")

        base_rule = {"protocol": "tcp", "target": "DROP"}

        # Isolates node server socket
        server_rule = {
            **base_rule,
            "dst": str(node.host),
            "src": str(other.node_client_host),
            "tcp": {"dport": str(node.node_port)},
        }

        # Isolates all node client sockets
        client_rule = {
            **base_rule,
            "dst": str(other.host),
            "src": str(node.node_client_host),
        }

        if iptc.easy.has_rule("filter", CCF_IPTABLES_CHAIN, server_rule):
            iptc.easy.delete_rule("filter", CCF_IPTABLES_CHAIN, server_rule)

        if iptc.easy.has_rule("filter", CCF_IPTABLES_CHAIN, client_rule):
            iptc.easy.delete_rule("filter", CCF_IPTABLES_CHAIN, client_rule)

        iptc.easy.insert_rule("filter", CCF_IPTABLES_CHAIN, server_rule)
        iptc.easy.insert_rule("filter", CCF_IPTABLES_CHAIN, client_rule)

    def create_partition(
        self,
        network: infra.network.Network,
        *args: List[infra.node.Node],
    ):
        if not args:
            raise ValueError("At least one partition should be specified")

        # Check that nodes only appear in one partition
        nodes = []
        for partition in args:
            nodes += partition
        if len(nodes) != len(set(nodes)):
            raise ValueError(f"Some nodes are repeated in multiple partitions")

        # Check that all nodes belong to network
        if not set(nodes).issubset(set(network.get_joined_nodes())):
            raise ValueError("Some nodes do not belong to network")

        # Also partition from nodes that are not explicitly passed in in a partition
        other_nodes = [node for node in network.get_joined_nodes() if node not in nodes]

        i = 1
        for partition in args:
            LOG.warning(f"Partitioning: {partition}")
            other_partitions = args[i:]
            LOG.info(f"Other partitions: {other_partitions}")

            for node in partition:
                LOG.success(f"Partitioning node: {node.local_node_id}")

                for other_partition in other_partitions:
                    for other_node in other_partition:
                        self.isolate_node_from_other(node, other_node)

                for other_node in other_nodes:
                    self.isolate_node_from_other(node, other_node)
            i += 1