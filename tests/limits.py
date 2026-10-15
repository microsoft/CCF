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

    cr.add(
        "transaction_size_limit",
        run_transaction_size_limit_checks,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
    )

    cr.run()
