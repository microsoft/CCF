# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.node
import iptc
import atexit

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

    def create_partition(self):
        pass
