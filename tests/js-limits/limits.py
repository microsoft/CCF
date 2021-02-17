# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import http
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs


@reqs.description("Test stack size limit")
def test_stack_size_limit(network, args):
    primary, _ = network.find_nodes()

    with primary.client("user0") as c:
        r = c.post("/app/recursive", body={"depth": 50})
        assert r.status_code == http.HTTPStatus.OK, r.status_code

    with primary.client("user0") as c:
        r = c.post("/app/recursive", body={"depth": 2000})
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r.status_code

    return network


@reqs.description("Test heap size limit")
def test_heap_size_limit(network, args):
    primary, _ = network.find_nodes()

    with primary.client("user0") as c:
        r = c.post("/app/alloc", body={"size": 5 * 1024 * 1024})
        assert r.status_code == http.HTTPStatus.OK, r.status_code

    with primary.client("user0") as c:
        r = c.post("/app/alloc", body={"size": 500 * 1024 * 1024})
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r.status_code

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_stack_size_limit(network, args)
        network = test_heap_size_limit(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "libjs_generic"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    run(args)
