# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import enum
import itertools
import json
import os
import threading
from dataclasses import field

import infra.network
import infra.node
import iptc
from loguru import logger as LOG

# Each Partitioner owns its own chain, so that several partitioned networks can
# run concurrently in one container without flushing each other's rules. The
# prefix is shared so that leftovers from a killed run can all be found.
CCF_IPTABLES_CHAIN_PREFIX = "CCF-TEST"

# iptables chain names are limited to 28 characters.
MAX_CHAIN_NAME_LENGTH = 28

_chain_counter = itertools.count()
_chain_counter_lock = threading.Lock()

# libiptc reads the whole table, modifies it and writes it back, so two threads
# committing at once can silently lose each other's rules. Every mutation of the
# filter table goes through this lock, which is enough because all partitioned
# networks in a test run live in one process (infra.runner.ConcurrentRunner
# threads).
_iptables_lock = threading.RLock()


def _next_chain_name():
    with _chain_counter_lock:
        index = next(_chain_counter)
    # The pid keeps chains distinct across concurrently running ctest processes,
    # the counter across Partitioners within one process.
    name = f"{CCF_IPTABLES_CHAIN_PREFIX}-{os.getpid()}-{index}"
    assert len(name) <= MAX_CHAIN_NAME_LENGTH, name
    return name


def _input_rule(chain_name):
    return {"protocol": "tcp", "target": chain_name}


def _delete_chain(chain_name):
    with _iptables_lock:
        if iptc.easy.has_chain("filter", chain_name):
            iptc.easy.flush_chain("filter", chain_name)
            if iptc.easy.has_rule("filter", "INPUT", _input_rule(chain_name)):
                iptc.easy.delete_rule("filter", "INPUT", _input_rule(chain_name))
            iptc.easy.delete_chain("filter", chain_name)


def _create_chain(chain_name):
    with _iptables_lock:
        iptc.easy.add_chain("filter", chain_name)
        iptc.easy.insert_rule("filter", "INPUT", _input_rule(chain_name))


def _replace_rule(chain_name, rule):
    with _iptables_lock:
        if iptc.easy.has_rule("filter", chain_name, rule):
            iptc.easy.delete_rule("filter", chain_name, rule)
        iptc.easy.insert_rule("filter", chain_name, rule)


def _drop_rule(chain_name, rule):
    with _iptables_lock:
        if iptc.easy.has_rule("filter", chain_name, rule):
            iptc.easy.delete_rule("filter", chain_name, rule)


def _ccf_chains():
    with _iptables_lock:
        return [
            chain
            for chain in iptc.easy.get_chains("filter")
            if chain.startswith(CCF_IPTABLES_CHAIN_PREFIX)
        ]


# Note: When playing with iptables rules on a remote VM, you may want to:
#   1. Save the current iptable rules: $ sudo iptables-save > /etc/iptables.conf
#   2. Setup a cron job to revert the iptables rules regularly, so that you cannot be
#      logged out of the VM, e.g.:
#      $ echo "* * * * * root /sbin/iptables-restore /etc/iptables.conf" | sudo tee -a /etc/cron.d/iptables-restore
# Warning: depending on the cron interval, this may cause partitions test to fail randomly as the iptables rules are
# deleted under the infra's feet.


class IsolationDir(enum.Flag):
    INBOUND_REQUESTS = enum.auto()
    INBOUND_RESPONSES = enum.auto()
    OUTBOUND_REQUESTS = enum.auto()
    OUTBOUND_RESPONSES = enum.auto()
    ALL = INBOUND_REQUESTS | INBOUND_RESPONSES | OUTBOUND_REQUESTS | OUTBOUND_RESPONSES


class Rules:
    """
    Set of iptables rules created by the :py:class:`infra.partitions.Partitioner`
    """

    rules: list[dict] = field(default_factory=list)

    name: str | None = None

    def __init__(self, rules, name=None, chain_name=None):
        self.rules = rules
        self.name = name
        self.chain_name = chain_name

    def __enter__(self):
        return self

    def __exit__(self, type_, value, traceback):
        self.drop()

    def drop(self):
        LOG.info(f'Dropping rules "{self.name or "[unamed]"}"')
        if self.chain_name is None:
            return
        for rule in self.rules:
            _drop_rule(self.chain_name, rule)


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

    Each instance owns a private iptables chain, so several partitioned networks
    may exist at once. Rules only ever match their own network's node addresses
    and ports, so co-existing chains do not affect each other.
    """

    def dump(self):
        if iptc.easy.has_chain("filter", self.chain_name):
            chain_status = (
                "active"
                if iptc.easy.has_rule("filter", "INPUT", _input_rule(self.chain_name))
                else "inactive"
            )
            LOG.info(
                f'Dumping {chain_status} chain {self.chain_name}:\n{json.dumps(iptc.easy.dump_chain("filter", self.chain_name), indent=2)}'
            )
        else:
            LOG.info(f"Chain {self.chain_name} does not exist")

    @staticmethod
    def dump_all():
        chains = _ccf_chains()
        if not chains:
            LOG.info(f"No {CCF_IPTABLES_CHAIN_PREFIX} iptables chain exists")
            return
        for chain_name in chains:
            chain_status = (
                "active"
                if iptc.easy.has_rule("filter", "INPUT", _input_rule(chain_name))
                else "inactive"
            )
            LOG.info(
                f'Dumping {chain_status} chain {chain_name}:\n{json.dumps(iptc.easy.dump_chain("filter", chain_name), indent=2)}'
            )

    def cleanup(self):
        _delete_chain(self.chain_name)
        LOG.info(f"{self.chain_name} iptables chain cleaned up")

    @staticmethod
    def cleanup_all():
        """Remove every chain this infrastructure may have left behind.

        Only safe to call when no partitioned network is running, so it is used
        by tests/cleanup_iptables.py rather than by the test infrastructure.
        """
        for chain_name in _ccf_chains():
            _delete_chain(chain_name)
        LOG.info(f"{CCF_IPTABLES_CHAIN_PREFIX} iptables chains cleaned up")

    @staticmethod
    def reverse_rule(rule):
        def swap_fields(obj, a, b):
            res = {**obj}
            if a in obj:
                res[b] = obj[a]
            else:
                del res[b]
            if b in obj:
                res[a] = obj[b]
            else:
                del res[a]
            return res

        r = swap_fields(rule, "src", "dst")

        if "tcp" in rule:
            r["tcp"] = swap_fields(rule["tcp"], "sport", "dport")

        return r

    def __init__(self, network):
        self.network = network
        self.chain_name = _next_chain_name()

        # Cleanup any leftover rules from a previous run that happened to reuse
        # this name
        _delete_chain(self.chain_name)

        # Create iptables chain, and the INPUT rule that jumps into it
        _create_chain(self.chain_name)

    def isolate_node(
        self,
        node: infra.node.Node,
        other: infra.node.Node | None = None,
        isolation_dir: IsolationDir = IsolationDir.ALL,
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
            "dst": node.n2n_interface.host,
            "tcp": {"dport": str(node.n2n_interface.port)},
        }

        # Isolates all node client sockets
        if not node.node_client_host:
            raise ValueError(f"Node {node.local_node_id} does not support partitioning")
        client_rule = {
            **base_rule,
            "src": node.node_client_host,
        }

        # If there is one, only isolate from specific node
        if other:
            server_rule["src"] = other.node_client_host
            client_rule["dst"] = other.n2n_interface.host
            name += f" from node {other.local_node_id}"

        rules = []
        if isolation_dir & IsolationDir.INBOUND_REQUESTS:
            rules.append(server_rule)
        if isolation_dir & IsolationDir.INBOUND_RESPONSES:
            rules.append(self.reverse_rule(server_rule))
        if isolation_dir & IsolationDir.OUTBOUND_REQUESTS:
            rules.append(client_rule)
        if isolation_dir & IsolationDir.OUTBOUND_RESPONSES:
            rules.append(self.reverse_rule(client_rule))

        for rule in rules:
            _replace_rule(self.chain_name, rule)

        LOG.debug(name)

        return Rules(rules, name, self.chain_name)

    @staticmethod
    def _get_partition_name(partition: list[infra.node.Node]):
        if not partition:
            return ""
        return f'[{",".join(str(node.local_node_id) for node in partition)}]'

    def partition(
        self,
        *args: list[infra.node.Node],
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
        if not set(nodes).issubset(set(self.network.nodes)):
            raise ValueError("Some nodes do not belong to network")

        # Also partition from nodes that are not explicitly passed in in a partition
        other_nodes = [
            node for node in self.network.get_live_nodes() if node not in nodes
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

        return Rules(rules, partition_name, self.chain_name)

    def partitions(self, *args: list[list[infra.node.Node]]):
        rule = Rules([], chain_name=self.chain_name)
        names = []
        for nodes in args:
            r = self.partition(*nodes)
            rule.rules.extend(r.rules)
            names.append(r.name)
        rule.name = ", ".join(names)
        return rule
