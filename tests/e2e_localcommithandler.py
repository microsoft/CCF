# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import http

from ccf.tx_id import TxID

import infra.checker
import infra.clients
import infra.crypto
import infra.e2e_args
import infra.jwt_issuer
import infra.logging_app as app
import infra.network
import infra.proc
import suite.test_requirements as reqs
from infra.runner import ConcurrentRunner


@reqs.description("Check safe increment, decrement and value")
@reqs.supports_methods("/app/increment", "/app/decrement", "/app/value")
@reqs.at_least_n_nodes(1)
def test_safe(network, args):
    primary, _ = network.find_primary()
    with primary.client() as c:
        r = c.post("/app/increment")
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        assert r.body.json()["value"] == 1
        TxID.from_str(r.body.json()["tx_id"])

        r = c.get("/app/value")
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        assert r.body.json()["value"] == 1
        TxID.from_str(r.body.json()["tx_id"])

        r = c.post("/app/decrement")
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        assert r.body.json()["value"] == 0
        TxID.from_str(r.body.json()["tx_id"])

        r = c.get("/app/value")
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        assert r.body.json()["value"] == 0
        TxID.from_str(r.body.json()["tx_id"])


@reqs.description("Check unsafe increment, decrement and value")
@reqs.supports_methods("/app/increment", "/app/decrement", "/app/value")
@reqs.at_least_n_nodes(1)
def test_unsafe(network, args):
    primary, _ = network.find_primary()
    with primary.client() as c:
        r = c.post("/app/increment_exception")
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR.value, r.status_code
        txid_header_key = "x-ms-ccf-transaction-id"
        # check we can parse the txid from the header
        # this gets set since the post-commit handler threw
        TxID.from_str(r.headers[txid_header_key])
        assert r.body.json() == {"error":{"code":"InternalError","message":"Failed to execute local commit handler func: oops, might have failed serialization"}}

        # should still be able to observe the value
        r = c.get("/app/value")
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        assert r.body.json()["value"] == 1
        TxID.from_str(r.body.json()["tx_id"])

        # and same for decrement
        r = c.post("/app/decrement_exception")
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR.value, r.status_code
        txid_header_key = "x-ms-ccf-transaction-id"
        # check we can parse the txid from the header
        # this gets set since the post-commit handler threw
        TxID.from_str(r.headers[txid_header_key])
        assert r.body.json() == {"error":{"code":"InternalError","message":"Failed to execute local commit handler func: oops, might have failed serialization"}}

        # should still be able to observe the value
        r = c.get("/app/value")
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        assert r.body.json()["value"] == 0
        TxID.from_str(r.body.json()["tx_id"])


def run(args):
    # set up nodes
    for local_node_id, node_host in enumerate(args.nodes):
        node_host.rpc_interfaces["default"] = infra.interfaces.RPCInterface(
            host=f"127.{local_node_id}.0.1",
            app_protocol=infra.interfaces.AppProtocol.HTTP2
            if args.http2
            else infra.interfaces.AppProtocol.HTTP1,
        )

    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)

        # the tests!
        test_safe(network, args)
        test_unsafe(network, args)

if __name__ == "__main__":
    cr = ConcurrentRunner()

    cr.add(
        "cpp",
        run,
        package="samples/apps/local_commit_handler/liblocalcommithandler",
        js_app_bundle=None,
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
    )

    cr.run()
