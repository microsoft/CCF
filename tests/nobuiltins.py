# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.logging_app as app
import infra.e2e_args
import infra.network
from http import HTTPStatus

from loguru import logger as LOG


def test_nobuiltins_endpoints(network, args):
    primary, _ = network.find_primary()
    with primary.client() as c:
        r = c.get("/app/node_summary")
        assert r.status_code == HTTPStatus.OK

        r = c.get("/app/api")
        assert r.status_code == HTTPStatus.OK
        
        r = c.get("/app/commit")
        assert r.status_code == HTTPStatus.OK
        
        r = c.get("/app/tx_id")
        assert r.status_code == HTTPStatus.OK


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        test_nobuiltins_endpoints(network, args)


if __name__ == "__main__":
    LOG.warning("Hello")
    args = infra.e2e_args.cli_args()

    LOG.warning(args.package)

    args.nodes = infra.e2e_args.min_nodes(args, f=0)
    run(args)
