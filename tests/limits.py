# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import copy
import http

import infra.checker
import infra.clients
import infra.crypto
import infra.e2e_args
import infra.jwt_issuer
import infra.network
import infra.proc
import suite.test_requirements as reqs
from infra.runner import ConcurrentRunner


def test_forward_larger_than_default_requests(network, args):
    new_node = network.create_node(
        infra.interfaces.HostSpec(
            rpc_interfaces={
                infra.interfaces.PRIMARY_RPC_INTERFACE: infra.interfaces.RPCInterface(
                    max_http_body_size=10 * 1024 * 1024,
                    # Deliberately large because some builds (eg. SGX Debug) take
                    # a long time to process large requests
                    forwarding_timeout_ms=8000,
                )
            }
        )
    )
    network.join_node(new_node, args.package, args, from_snapshot=False)
    network.trust_node(new_node, args)

    primary, _ = network.find_primary()

    def get_request_payload_too_large_errors():
        with primary.client() as c:
            return c.get("/node/metrics").body.json()["sessions"]["interfaces"][
                infra.interfaces.PRIMARY_RPC_INTERFACE
            ]["errors"]["request_payload_too_large"]

    # Big request, but under the cap
    with primary.client("user0") as c:
        msg = "A" * 512 * 1024
        r = c.post("/app/log/private", {"id": 42, "msg": msg})
        assert r.status_code == http.HTTPStatus.OK.value, r

    # Big request, over the cap for the primary
    msg = "A" * 2 * 1024 * 1024
    before_errors_count = get_request_payload_too_large_errors()
    try:
        with primary.client("user0") as c:
            r = c.post("/app/log/private", {"id": 42, "msg": msg})
    except infra.clients.CCFIOException:
        # The server may close before the client finishes writing the rejected
        # body, so confirm the rejection through the interface error metric.
        assert get_request_payload_too_large_errors() == before_errors_count + 1
    else:
        assert r.status_code == http.HTTPStatus.REQUEST_ENTITY_TOO_LARGE.value, r

    # Big request, over the cap for the primary, but under the cap for the new node
    with new_node.client("user0") as c:
        msg = "A" * 2 * 1024 * 1024
        r = c.post("/app/log/private", {"id": 42, "msg": msg})
        assert r.status_code == http.HTTPStatus.OK.value, r


@reqs.description("Transactions larger than ledger.max_transaction_size are rejected")
@reqs.supports_methods("/app/log/private")
def test_transaction_size_limit(network, args):
    primary, _ = network.find_primary()

    with primary.client("user0") as c:
        r = c.post("/app/log/private", {"id": 1, "msg": "small"})
        assert r.status_code == http.HTTPStatus.OK.value, r

        # Comfortably under the interface's max_http_body_size, so this is
        # rejected by the ledger transaction size limit rather than by the HTTP
        # request parser, which reports RequestBodyTooLarge and closes the
        # session.
        msg = "A" * 600 * 1024
        r = c.post("/app/log/private", {"id": 2, "msg": msg})
        assert r.status_code == http.HTTPStatus.REQUEST_ENTITY_TOO_LARGE.value, r
        assert r.body.json()["error"]["code"] == "TransactionTooLarge", r

        # The rejected transaction was never applied, so it neither wrote a
        # value nor prevented later transactions from being processed
        r = c.get("/app/log/private?id=2")
        assert r.status_code == http.HTTPStatus.NOT_FOUND.value, r

        r = c.post("/app/log/private", {"id": 3, "msg": "still processing"})
        assert r.status_code == http.HTTPStatus.OK.value, r

        r = c.get("/app/log/private?id=3")
        assert r.status_code == http.HTTPStatus.OK.value, r
        assert r.body.json()["msg"] == "still processing", r


def run_parser_limits_checks(args):
    new_args = copy.copy(args)
    # Deliberately large because some builds take
    # a long time to process large requests
    new_args.election_timeout_ms = 10000
    new_args.log_level = "info"
    with infra.network.network(
        new_args.nodes,
        new_args.binary_dir,
        new_args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(new_args)

        test_forward_larger_than_default_requests(network, new_args)


def run_transaction_size_limit_checks(args):
    new_args = copy.copy(args)
    # Larger than the constitution scripts written to the KV store as part of
    # service creation, and than any governance transaction, but smaller than
    # the oversized request used by the test
    new_args.ledger_max_transaction_bytes = "512KB"
    with infra.network.network(
        new_args.nodes,
        new_args.binary_dir,
        new_args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(new_args)

        test_transaction_size_limit(network, new_args)


if __name__ == "__main__":
    cr = ConcurrentRunner()

    if not cr.args.http2:
        # No support for forwarding with HTTP/2
        cr.add(
            "parser_limits",
            run_parser_limits_checks,
            package="samples/apps/logging/logging",
            nodes=infra.e2e_args.max_nodes(cr.args, f=0),
        )

    cr.add(
        "transaction_size_limit",
        run_transaction_size_limit_checks,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
    )

    cr.run()
