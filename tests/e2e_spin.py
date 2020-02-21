# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.ccf
import infra.notification
import suite.test_requirements as reqs
import infra.logging_app as app
import infra.e2e_args

from loguru import logger as LOG


@reqs.description("Check slow/expensive transactions do not cause an eleection")
@reqs.supports_methods("SmallBank_spin")
def test_large_messages(network, args):
    primary, _ = network.find_primary()

    with primary.node_client() as nc:
        check_commit = infra.checker.Checker(nc)
        check = infra.checker.Checker()

        with primary.user_client(request_timeout=10) as c:
            primary = c.rpc("getPrimaryInfo", {}).result["primary_host"]
            c.rpc("SmallBank_spin", {"iterations": 800_000_000})
            new_primary = c.rpc("getPrimaryInfo", {}).result["primary_host"]
            assert primary == new_primary

    return network


def run(args):
    hosts = ["localhost"] * (4 if args.consensus == "pbft" else 2)

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb,
    ) as network:
        network.start_and_join(args)
        network = test_large_messages(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "libsmallbank"
    args.election_timeout = 1000
    run(args)
