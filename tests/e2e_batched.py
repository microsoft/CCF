# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import functools
import infra.ccf
import infra.proc
import infra.jsonrpc
import infra.notification
import infra.net
import suite.test_requirements as reqs
import e2e_args

from loguru import logger as LOG


@reqs.lua_generic_app
def test(network, args):
    LOG.info("Running transactions against batched app")
    primary, _ = network.find_primary()

    with primary.node_client() as mc:
        pass

    return network


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        network = test(network, args)


if __name__ == "__main__":
    args = e2e_args.cli_args()
    args.package = "libluagenericenc"
    args.enforce_reqs = True

    run(args)
