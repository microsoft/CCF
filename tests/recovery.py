# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import getpass
import os
import time
import logging
import multiprocessing
import e2e_args
from random import seed
import infra.ccf
import infra.proc
import infra.remote
import json
import suite.test_requirements as reqs

from loguru import logger as LOG


class Txs:
    def __init__(self, nb_msgs, offset=0, since_beginning=False):
        self.pub = {}
        self.priv = {}

        # After a recovery, check that all messages since the beginning of
        # time have been successfully recovered
        start_i = (offset * nb_msgs) if not since_beginning else 0

        for i in range(start_i, nb_msgs + offset * nb_msgs):
            self.pub[i] = "Public msg #{}".format(i)
            self.priv[i] = "Private msg #{}".format(i)


def check_nodes_have_msgs(nodes, txs):
    """
    Read and check values for messages at an offset. This effectively
    makes sure nodes have recovered state.
    """
    for node in nodes:
        with node.user_client(format="json") as c:
            for n, msg in txs.priv.items():
                c.do(
                    "LOG_get",
                    {"id": n},
                    readonly_hint=None,
                    expected_result={"msg": msg},
                )
            for n, msg in txs.pub.items():
                c.do(
                    "LOG_get_pub",
                    {"id": n},
                    readonly_hint=None,
                    expected_result={"msg": msg},
                )


def log_msgs(primary, txs):
    """
    Log a new series of messages
    """
    LOG.debug("Applying new transactions")
    responses = []
    with primary.user_client(format="json") as c:
        for n, msg in txs.priv.items():
            responses.append(c.rpc("LOG_record", {"id": n, "msg": msg}))
        for n, msg in txs.pub.items():
            responses.append(c.rpc("LOG_record_pub", {"id": n, "msg": msg}))
    return responses


def check_responses(responses, result, check, check_commit):
    for response in responses[:-1]:
        check(response, result=result)
    check_commit(responses[-1], result=result)


@reqs.none
def test(network, args):
    LOG.info("Starting network recovery")

    primary, backups = network.find_nodes()

    ledger = primary.remote.get_ledger()
    sealed_secrets = primary.remote.get_sealed_secrets()

    recovered_network = infra.ccf.Network(
        network.hosts, args.debug_nodes, args.perf_nodes, network
    )
    recovered_network.start_in_recovery(args, ledger, sealed_secrets)

    for node in recovered_network.nodes:
        recovered_network.wait_for_state(node, "partOfPublicNetwork")
        recovered_network.wait_for_node_commit_sync()
    LOG.info("Public CFTR started")

    primary, term = recovered_network.find_primary()

    LOG.info("Members verify that the new nodes have joined the network")
    recovered_network.wait_for_all_nodes_to_be_trusted()

    LOG.info("Members vote to complete the recovery")
    recovered_network.consortium.accept_recovery(
        member_id=1, remote_node=primary, sealed_secrets=sealed_secrets
    )

    for node in recovered_network.nodes:
        network.wait_for_state(node, "partOfNetwork")

    recovered_network.wait_for_all_nodes_to_catch_up(primary)

    recovered_network.consortium.check_for_service(
        primary, infra.ccf.ServiceStatus.OPEN
    )
    LOG.success("Network successfully recovered")

    return recovered_network


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        for recovery_idx in range(args.recovery):
            txs = Txs(args.msgs_per_recovery, recovery_idx)

            primary, backups = network.find_nodes()

            with primary.node_client() as mc:
                check_commit = infra.checker.Checker(mc)
                check = infra.checker.Checker()

                rs = log_msgs(primary, txs)
                check_responses(rs, True, check, check_commit)
                network.wait_for_node_commit_sync()
                check_nodes_have_msgs(backups, txs)

            recovered_network = test(network, args)

            network.stop_all_nodes()
            network = recovered_network

            old_txs = Txs(args.msgs_per_recovery, recovery_idx, since_beginning=True)

            check_nodes_have_msgs(recovered_network.nodes, old_txs)
            LOG.success("Recovery complete on all nodes")


if __name__ == "__main__":

    def add(parser):
        parser.description = """
This test executes multiple recoveries (as specified by the "--recovery" arg),
with a fixed number of messages applied between each network crash (as
specified by the "--msgs-per-recovery" arg). After the network is recovered
and before applying new transactions, all transactions previously applied are
checked. Note that the key for each logging message is unique (per table).
"""
        parser.add_argument(
            "--recovery", help="Number of recoveries to perform", type=int, default=2
        )
        parser.add_argument(
            "--msgs-per-recovery",
            help="Number of public and private messages between two recoveries",
            type=int,
            default=5,
        )

    args = e2e_args.cli_args(add)
    args.package = "libloggingenc"
    run(args)
