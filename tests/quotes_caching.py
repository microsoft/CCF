# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import sys
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs
import time

from loguru import logger as LOG


@reqs.description("Test quotes")
@reqs.supports_methods("quotes/self", "quotes")
def test_quotes_caching(network, args):
    primary, _ = network.find_nodes()
    out = primary.remote.remote.out
    rv = infra.proc.ccall("grep", "-c", "GETTING CODE ID", out)
    assert rv.stdout.decode().strip() == "1", rv.stdout
    with primary.client() as c:
        for _ in range(100):
            r = c.get("/node/quotes")
            assert r.status_code == 200
    # Make sure log lines are flushed
    primary.stop()
    time.sleep(5)
    rv = infra.proc.ccall("grep", "-c", "GETTING CODE ID", out)
    assert rv.stdout.decode().strip() == "1", rv.stdout

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_quotes_caching(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    if args.enclave_type == "virtual":
        LOG.warning("This test can only run in real enclaves, skipping")
        sys.exit(0)

    args.package = "liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.initial_user_count = 3
    run(args)
