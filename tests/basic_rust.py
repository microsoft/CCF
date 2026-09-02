# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import http
import re

import infra.e2e_args
import infra.network
import suite.test_requirements as reqs


@reqs.description("Exercise Rust application endpoints and KV access")
@reqs.supports_methods("/app/health", "/app/panic", "/app/records/{key}")
def test_basic_rust(network, args):
    primary, _ = network.find_primary()

    with primary.client() as anonymous:
        response = anonymous.get("/app/panic")
        assert response.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, response

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
    try:
        with infra.network.network(
            args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
        ) as network:
            network.start_and_open(args)
            test_basic_rust(network, args)
    except infra.network.NetworkShutdownError as error:
        # catch_unwind contains the panic, but Rust's default hook still writes
        # the panic report to stderr.
        fatal_errors = [
            line.strip()
            for node_errors in (error.errors or {}).values()
            for line in node_errors
            if line.strip()
        ]
        assert len(fatal_errors) == 3, fatal_errors
        assert re.fullmatch(
            r"thread '<unnamed>'(?: \(\d+\))? panicked at src/lib\.rs:\d+:\d+:",
            fatal_errors[0],
        ), fatal_errors
        assert fatal_errors[1:] == [
            "test panic",
            "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace",
        ], fatal_errors


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "samples/apps/basic_rust/basic_rust"
    args.nodes = infra.e2e_args.min_nodes(args, f=0)
    run(args)
