# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import http

import infra.e2e_args
import infra.network
import suite.test_requirements as reqs


@reqs.description("Exercise Rust application endpoints and KV access")
@reqs.supports_methods("/app/health", "/app/records/{key}")
def test_basic_rust(network, args):
    primary, _ = network.find_primary()

    with primary.client() as anonymous:
        response = anonymous.get("/app/health")
        assert response.status_code == http.HTTPStatus.OK, response
        assert response.body.data() == b"OK", response.body

        response = anonymous.get("/app/records/missing")
        assert response.status_code == http.HTTPStatus.UNAUTHORIZED, response

    with primary.client("user0") as user:
        value = b"\x00rust\xff"
        response = user.put("/app/records/example", body=value)
        assert response.status_code == http.HTTPStatus.NO_CONTENT, response

        response = user.get("/app/records/example")
        assert response.status_code == http.HTTPStatus.OK, response
        assert response.body.data() == value, response.body

        response = user.get("/app/records/missing")
        assert response.status_code == http.HTTPStatus.NOT_FOUND, response

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        test_basic_rust(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "samples/apps/basic_rust/basic_rust"
    args.nodes = infra.e2e_args.min_nodes(args, f=0)
    run(args)
