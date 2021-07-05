# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import http
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs


@reqs.description("Test custom authorization")
def test_custom_auth(network, args):
    primary, _ = network.find_nodes()

    with primary.client("user0") as c:
        r = c.get("/app/custom_auth", headers={"Authorization": "Bearer 42"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body.json()

    return network


def run(args):
    with infra.network.network(
        args.nodes,
        args.consensus,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_join(args)
        network = test_custom_auth(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "libjs_generic"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    run(args)
