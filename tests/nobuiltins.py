# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.logging_app as app
import infra.e2e_args
import infra.network
from http import HTTPStatus
import openapi_spec_validator

from loguru import logger as LOG


def test_nobuiltins_endpoints(network, args):
    primary, _ = network.find_primary()
    with primary.client() as c:
        r = c.get("/app/commit")
        assert r.status_code == HTTPStatus.OK
        body_j = r.body.json()
        view = body_j["view"]
        seqno = body_j["seqno"]

        r = c.get("/app/node_summary")
        assert r.status_code == HTTPStatus.OK
        body_j = r.body.json()
        assert body_j["committed_view"] == view
        assert body_j["committed_seqno"] == seqno
        assert body_j["quote_format"] == "OE_SGX_v1"

        r = c.get("/app/api")
        assert r.status_code == HTTPStatus.OK
        openapi_spec_validator.validate_spec(r.body.json())
        
        r = c.get(f"/app/tx_id?seqno={seqno}")
        assert r.status_code == HTTPStatus.OK
        body_j = r.body.json()
        assert body_j["transaction_id"] == f"{view}.{seqno}"


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        test_nobuiltins_endpoints(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.nodes = infra.e2e_args.min_nodes(args, f=0)
    run(args)
