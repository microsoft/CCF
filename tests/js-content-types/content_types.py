# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import http
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs


@reqs.description("Test content types")
def test_content_types(network, args):
    primary, _ = network.find_nodes()

    with primary.client("user0") as c:
        r = c.post("/app/text", body="text")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "text/plain"
        assert r.body.text() == "text"

        r = c.post("/app/json", body={"foo": "bar"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "application/json"
        assert r.body.json() == {"foo": "bar"}

        r = c.post("/app/binary", body=b"\x00" * 42)
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "application/octet-stream"
        assert r.body.data() == b"\x00" * 42, r.body

        r = c.post("/app/custom", body="text", headers={"content-type": "foo/bar"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "text/plain"
        assert r.body.text() == "text"

    return network


@reqs.description("Test unknown path")
def test_unknown_path(network, args):
    primary, _ = network.find_nodes()

    with primary.client("user0") as c:
        r = c.get("/app/not/a/real/path")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code
        r = c.post("/app/not/a/real/path")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code
        r = c.delete("/app/not/a/real/path")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code

        r = c.post("/app/unknown")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code

    with primary.client() as c:
        r = c.get("/app/not/a/real/path")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code
        r = c.post("/app/not/a/real/path")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code
        r = c.delete("/app/not/a/real/path")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code

        r = c.post("/app/unknown")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code

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
        network = test_content_types(network, args)
        network = test_unknown_path(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "libjs_generic"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    run(args)
