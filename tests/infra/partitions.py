# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.node
import infra.network
import iptc
import json
from dataclasses import field
from typing import List, Optional

from loguru import logger as LOG


CCF_IPTABLES_CHAIN = "CCF-TEST"

CCF_INPUT_RULE = {
    "protocol": "tcp",
    "target": CCF_IPTABLES_CHAIN,
}

# Note: When playing with iptables rules on a remote VM, you may want to:
#   1. Save the current iptable rules: $ sudo iptables-save > /etc/iptables.conf
#   2. Setup a cron job to revert the iptables rules regularly, so that you cannot be
#      logged out of the VM, e.g.:
#      $ echo "* * * * * root /sbin/iptables-restore /etc/iptables.conf" | sudo tee -a /etc/cron.d/iptables-restore
# Warning: depending on the cron interval, this may cause partitions test to fail randomly as the iptables rules are
# deleted under the infra's feet.


class Rules:
    """
    Set of iptables rules created by the :py:class:`infra.partitions.Partitioner`
    """

    rules: List[dict] = field(default_factory=list)

    name: Optional[str] = None

    def __init__(self, rules, name=None):
        self.rules = rules
        self.name = name

    def __enter__(self):
        return self

    def __exit__(self, type_, value, traceback):
        self.drop()

    def drop(self):
        LOG.info(f'Dropping rules "{self.name or "[unamed]"}"')
        for rule in self.rules:
            if iptc.easy.has_rule("filter", CCF_IPTABLES_CHAIN, rule):
                iptc.easy.delete_rule("filter", CCF_IPTABLES_CHAIN, rule)


class Partitioner:
    """
    The :py:class:`infra.partitions.Partitioner` provides a convenient way to isolate and
    create partitions of :py:class:`infra.node.Node` objects. As it relies on iptables,
    using this class requires admin privileges.

    All member functions return a :py:class:`infra.partitions.Rules` object that can be used
    in a context manager and which will be automatically dropped when the object goes out of
    scope.

    Note: It should be managed by a :py:class:`infra.network.Network` instance so that rules
    outlive nodes to avoid spurious log messages when the network is shutdown.
    """

    @staticmethod
    def dump():
        if iptc.easy.has_chain("filter", CCF_IPTABLES_CHAIN):
            chain_status = (
                "active"
                if iptc.easy.has_rule("filter", "INPUT", CCF_INPUT_RULE)
                else "inactive"
            )
            LOG.info(
                f'Dumping {chain_status} chain {CCF_IPTABLES_CHAIN}:\n{json.dumps(iptc.easy.dump_chain("filter", CCF_IPTABLES_CHAIN), indent=2)}'
            )
        else:
            LOG.info(f"Chain {CCF_IPTABLES_CHAIN} does not exist")

    @staticmethod
    def cleanup():
        if iptc.easy.has_chain("filter", CCF_IPTABLES_CHAIN):
            iptc.easy.flush_chain("filter", CCF_IPTABLES_CHAIN)
            iptc.easy.delete_rule("filter", "INPUT", CCF_INPUT_RULE)
            iptc.easy.delete_chain("filter", CCF_IPTABLES_CHAIN)
        LOG.info(f"{CCF_IPTABLES_CHAIN} iptables chain cleaned up")

    def __init__(self, network):
        self.network = network

        # Cleanup any leftover rules
        self.cleanup()

        # Create iptables chain
        iptc.easy.add_chain("filter", CCF_IPTABLES_CHAIN)

        # Create iptables rule in INPUT chain
        iptc.easy.insert_rule("filter", "INPUT", CCF_INPUT_RULE)

    def isolate_node(
        self,
        node: infra.node.Node,
        other: Optional[infra.node.Node] = None,
    ):
        """
        Isolates a single :py:class:`infra.node.Node` from the network, or from a specific other node if specified.

        :param infra.node.Node node: The :py:class:`infra.node.Node` to isolate.
        :param Optional[infra.node.Node] other: The other node to isolate node from (optional).

        :return: :py:class:`infra.partitions.Rules`
        """
        if node is other:
            return None

        base_rule = {"protocol": "tcp", "target": "DROP"}
        name = f"Isolate node {node.local_node_id}"

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
            name += f" from node {other.local_node_id}"

        if iptc.easy.has_rule("filter", CCF_IPTABLES_CHAIN, server_rule):
            iptc.easy.delete_rule("filter", CCF_IPTABLES_CHAIN, server_rule)

        if iptc.easy.has_rule("filter", CCF_IPTABLES_CHAIN, client_rule):
            iptc.easy.delete_rule("filter", CCF_IPTABLES_CHAIN, client_rule)

        iptc.easy.insert_rule("filter", CCF_IPTABLES_CHAIN, server_rule)
        iptc.easy.insert_rule("filter", CCF_IPTABLES_CHAIN, client_rule)

        LOG.trace(name)
        return Rules([server_rule, client_rule], name)

    @staticmethod
    def _get_partition_name(partition: List[infra.node.Node]):
        if not partition:
            return ""
        return f'[{",".join(str(node.local_node_id) for node in partition)}]'

    def partition(
        self,
        *args: List[infra.node.Node],
        name=None,
    ):
        """
        Creates an arbitrary number of partitions of :py:class:`infra.node.Node`. All other joined nodes in the
        :py:class:`infra.network.Network` are also isolated in their own partition.

        :param List[infra.node.Node] *args: A variable length argument list of :py:class:`infra.node.Node` (i.e. partitions) to isolate.
        :param str name: Name of the partition rules (optional, otherwise constructed by the test).

        :return: :py:class:`infra.partitions.Rules`
        """
        if not args:
            raise ValueError("At least one partition should be specified")

        # Check that nodes only appear in one partition
        nodes = []
        for partition in args:
            nodes += partition
        if len(nodes) != len(set(nodes)):
            raise ValueError("Some nodes are repeated in multiple partitions")

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
                        rules.extend(self.isolate_node(node, other_node).rules)

                for other_node in other_nodes:
                    rules.extend(self.isolate_node(node, other_node).rules)

        partitions_name.append(self._get_partition_name(other_nodes))

        # Override partition name if it is specified by the caller
        partition_name = name or ",".join(partitions_name)

        LOG.success(f"Created new partition {partition_name}")

        return Rules(rules, partition_name)
