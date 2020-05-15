# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.ccf
import infra.logging_app as app
import suite.test_requirements as reqs

from loguru import logger as LOG


@reqs.description("Recovering a network")
@reqs.recover(number_txs=2)
def test(network, args):
    primary, _ = network.find_primary()
    ledger = primary.get_ledger()

    recovered_network = infra.ccf.Network(
        network.hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, network
    )
    recovered_network.start_in_recovery(args, ledger)
    return recovered_network


def run(args):
    hosts = ["localhost", "localhost"]

    txs = app.LoggingTxs()

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb, txs=txs
    ) as network:
        network.start_and_join(args)

        for _ in range(args.recovery):
            recovered_network = test(network, args)
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

    args = infra.e2e_args.cli_args(add)
    args.package = "liblogging"

    run(args)
