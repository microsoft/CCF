# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.node
import infra.network
import iptc
from dataclasses import dataclass, field
from contextlib import contextmanager
from typing import List, Optional

from loguru import logger as LOG


CCF_IPTABLES_CHAIN = "CCF-TEST"

CCF_INPUT_RULE = {
    "protocol": "tcp",
    "target": CCF_IPTABLES_CHAIN,
}


@dataclass
class Rules:
    rules: List[dict] = field(default_factory=list)

    name: Optional[str] = None

    def drop(self):
        LOG.info(f'Dropping rules "{self.name or "[unamed]"}"')
        for rule in self.rules:
            if iptc.easy.has_rule("filter", CCF_IPTABLES_CHAIN, rule):
                iptc.easy.delete_rule("filter", CCF_IPTABLES_CHAIN, rule)


class Partitioner:
    @staticmethod
    def cleanup(sig=None, frame=None):
        if iptc.easy.has_chain("filter", CCF_IPTABLES_CHAIN):
            iptc.easy.flush_chain("filter", CCF_IPTABLES_CHAIN)
            iptc.easy.delete_rule("filter", "INPUT", CCF_INPUT_RULE)
            iptc.easy.delete_chain("filter", CCF_IPTABLES_CHAIN)
        LOG.info(f"{CCF_IPTABLES_CHAIN} iptables chain cleaned up")

    def __init__(self, network):
        self.network = network
        # Create iptables chain
        if not iptc.easy.has_chain("filter", CCF_IPTABLES_CHAIN):
            iptc.easy.add_chain("filter", CCF_IPTABLES_CHAIN)

        # TODO: Check it hasn't got the rule already
        if not iptc.easy.has_rule("filter", "INPUT", CCF_INPUT_RULE):
            iptc.easy.insert_rule("filter", "INPUT", CCF_INPUT_RULE)

    def isolate_node_from_other(
        self,
        node: infra.node.Node,
        other: Optional[infra.node.Node],
    ):
        if node is other:
            return None

        base_rule = {"protocol": "tcp", "target": "DROP"}
        msg = f"Isolate node {node.local_node_id}"

        # Isolates node server socket
        server_rule = {
            **base_rule,
            "dst": node.host,
            "tcp": {"dport": str(node.node_port)},
        }

        # Isolates all node client sockets
        client_rule = {
            **base_rule,
            "src": node.node_client_host,
        }

        # If there is one, only isolate from specific node
        if other:
            server_rule["src"] = other.node_client_host
            client_rule["dst"] = other.host
            msg += f" from node {other.local_node_id}"

        if iptc.easy.has_rule("filter", CCF_IPTABLES_CHAIN, server_rule):
            iptc.easy.delete_rule("filter", CCF_IPTABLES_CHAIN, server_rule)

        if iptc.easy.has_rule("filter", CCF_IPTABLES_CHAIN, client_rule):
            iptc.easy.delete_rule("filter", CCF_IPTABLES_CHAIN, client_rule)

        iptc.easy.insert_rule("filter", CCF_IPTABLES_CHAIN, server_rule)
        iptc.easy.insert_rule("filter", CCF_IPTABLES_CHAIN, client_rule)

        LOG.info(msg)

        return Rules([server_rule, client_rule], msg)

    @staticmethod
    def _get_partition_name(partition: List[infra.node.Node]):
        if not partition:
            return ""
        return f'[{",".join(str(node.local_node_id) for node in partition)}]'

    def partition(
        self,
        *args: List[infra.node.Node],
        **kwargs,
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
        if not set(nodes).issubset(set(self.network.get_joined_nodes())):
            raise ValueError("Some nodes do not belong to network")

        # Also partition from nodes that are not explicitly passed in in a partition
        other_nodes = [
            node for node in self.network.get_joined_nodes() if node not in nodes
        ]

        rules = []
        partitions_name = []
        for i, partition in enumerate(args):
            partitions_name.append(f"{self._get_partition_name(partition)}")
            # Rules are bi-directional so skip partitions that have already been enforced
            other_partitions = args[i + 1 :]

            for node in partition:
                for other_partition in other_partitions:
                    for other_node in other_partition:
                        rules.extend(
                            self.isolate_node_from_other(node, other_node).rules
                        )

                for other_node in other_nodes:
                    rules.extend(self.isolate_node_from_other(node, other_node).rules)

        partitions_name.append(self._get_partition_name(other_nodes))

        # TODO: name contains trailing comma
        LOG.success(f'Created new partition {",".join(partitions_name)}')

        return Rules(
            rules,
            kwargs.get("name", f'partition {",".join(partitions_name)}'),
        )


@contextmanager
def partitioner(network):
    p = Partitioner(network)

    try:
        yield p
    except Exception:
        raise
    finally:
        p.cleanup()
