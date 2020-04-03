# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import getpass
import os
import time
import logging
import multiprocessing
import infra.e2e_args
from random import seed
import infra.ccf
import infra.logging_app as app
import json
import suite.test_requirements as reqs

from loguru import logger as LOG


@reqs.description("Recovering a network")
@reqs.recover(number_txs=2)
def test(network, args, use_shares=False):
    if use_shares:
        LOG.warning("Using member key shares for recovery (experimental)")

    primary, backups = network.find_nodes()

    ledger = primary.get_ledger()
    sealed_secrets = primary.get_sealed_secrets()

    if use_shares:
        network.consortium.store_current_network_encryption_key()

    recovered_network = infra.ccf.Network(
        network.hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, network
    )
    recovered_network.start_in_recovery(args, ledger, sealed_secrets)

    for node in recovered_network.nodes:
        recovered_network.wait_for_state(node, "partOfPublicNetwork")
        recovered_network.wait_for_node_commit_sync(args.consensus)
    LOG.info("Public CFTR started")

    primary, term = recovered_network.find_primary()

    LOG.info("Members verify that the new nodes have joined the network")
    recovered_network.wait_for_all_nodes_to_be_trusted()

    if use_shares:
        LOG.warning("Retrieve and submit recovery shares")
        recovered_network.consortium.accept_recovery_with_shares(remote_node=primary)
        recovered_network.consortium.recover_with_shares(remote_node=primary)
    else:
        LOG.info("Members vote to complete the recovery")
        recovered_network.consortium.accept_recovery(
            remote_node=primary, sealed_secrets=sealed_secrets
        )

    for node in recovered_network.nodes:
        recovered_network.wait_for_state(node, "partOfNetwork")

    recovered_network.wait_for_all_nodes_to_catch_up(primary)

    recovered_network.consortium.check_for_service(
        primary, infra.ccf.ServiceStatus.OPEN
    )
    LOG.success("Network successfully recovered")

    return recovered_network


def run(args):
    hosts = ["localhost", "localhost"]

    txs = app.LoggingTxs()

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb, txs=txs
    ) as network:
        network.start_and_join(args)

        for recovery_idx in range(args.recovery):
            recovered_network = test(network, args, use_shares=args.use_shares)
            network.stop_all_nodes()
            network = recovered_network

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
        parser.add_argument(
            "--use-shares",
            help="Use member key shares (experimental)",
            action="store_true",
        )

    args = infra.e2e_args.cli_args(add)
    args.package = "liblogging"

    run(args)
