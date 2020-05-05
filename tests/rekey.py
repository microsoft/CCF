# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.ccf
import infra.notification
import suite.test_requirements as reqs
import infra.e2e_args
import e2e_logging


@reqs.description("Rekey the ledger once")
@reqs.supports_methods("mkSign")
@reqs.at_least_n_nodes(1)
def test(network, args):
    primary, _ = network.find_primary()
    network.consortium.rekey_ledger(primary)
    return network

def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb,
    ) as network:
        network.start_and_join(args)

        network = e2e_logging.test(network, args)
        network = test(network, args)
        network = e2e_logging.test(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = args.app_script and "liblua_generic" or "liblogging"
    run(args)
