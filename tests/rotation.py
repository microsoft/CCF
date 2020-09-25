# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import suite.test_requirements as reqs
import reconfiguration
import e2e_logging

from loguru import logger as LOG


@reqs.description("Suspend and resume primary")
@reqs.at_least_n_nodes(3)
def test_suspend_primary(network, args):
    primary, _ = network.find_primary()
    primary.suspend()
    new_primary, new_term = network.wait_for_new_primary(primary.node_id)
    LOG.debug(f"New primary is {new_primary.node_id} in term {new_term}")
    reconfiguration.check_can_progress(new_primary)
    primary.resume()
    reconfiguration.check_can_progress(new_primary)
    return network


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        """
        reconfiguration.test_add_node(network, args)
        e2e_logging.test_view_history(network, args)
        reconfiguration.test_retire_primary(network, args)
        e2e_logging.test_view_history(network, args)
        """
        # Replace primary repeatedly and check the network still operates
        for _ in range(10):
            reconfiguration.test_add_node(network, args)
            reconfiguration.test_retire_primary(network, args)

        
        reconfiguration.test_add_node(network, args)
        # Suspend primary repeatedly and check the network still operates
        for _ in range(10):
            test_suspend_primary(network, args)


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., liblogging)",
            default="liblogging",
        )

    args = infra.e2e_args.cli_args(add)
    args.package = args.app_script and "liblua_generic" or "liblogging"
    run(args)
