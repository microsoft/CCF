# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import suite.test_requirements as reqs
import infra.logging_app as app
import infra.e2e_args


@reqs.description("Rekey the ledger once")
@reqs.supports_methods("primary_info")
@reqs.at_least_n_nodes(1)
def test(network, args):
    primary, _ = network.find_primary()
    network.consortium.rekey_ledger(primary)
    return network


def run(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_join(args)

        txs = app.LoggingTxs()
        txs.issue(
            network=network,
            number_txs=3,
        )
        txs.verify()

        network = test(network, args)

        txs.issue(
            network=network,
            number_txs=3,
        )
        txs.verify()


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    run(args)
