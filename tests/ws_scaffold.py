# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.proc
import infra.net
import suite.test_requirements as reqs
import infra.e2e_args
import time

from loguru import logger as LOG


@reqs.description("Running transactions against logging app")
@reqs.supports_methods("log/private")
@reqs.at_least_n_nodes(2)
def test(network, args):
    primary, other = network.find_primary_and_any_backup()

    msg = "Hello world"
    LOG.info("Write on primary")
    with primary.client("user0", ws=True) as c:
        for i in [1, 50, 500]:
            r = c.post("/app/log/private", {"id": 42, "msg": msg * i})
            assert r.body.json() == True, r

    # Before we start sending transactions to the secondary,
    # we want to wait for its app frontend to be open, which is
    # when it's aware that the network is open. Before that,
    # we will get 404s.
    end_time = time.time() + 10
    with other.client("user0") as nc:
        while time.time() < end_time:
            r = nc.post("/app/log/private", {"id": 42, "msg": msg * i})
            if r.status_code == 200:
                break
            else:
                time.sleep(0.1)
        assert r.status_code == 200, r

    LOG.info("Write on secondary through forwarding")
    with other.client("user0", ws=True) as c:
        for i in [1, 50, 500]:
            r = c.post("/app/log/private", {"id": 42, "msg": msg * i})
            assert r.body.json() == True, r

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        test(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    run(args)
