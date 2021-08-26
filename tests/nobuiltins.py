# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
from ccf.tx_id import TxID
from http import HTTPStatus
import openapi_spec_validator
from datetime import datetime, timezone
import time


def test_nobuiltins_endpoints(network, args):
    primary, backups = network.find_nodes()
    with primary.client() as c:
        r = c.get("/app/commit")
        assert r.status_code == HTTPStatus.OK
        body_j = r.body.json()
        tx_id = TxID.from_str(body_j["transaction_id"])

        r = c.get("/app/node_summary")
        assert r.status_code == HTTPStatus.OK
        body_j = r.body.json()
        assert body_j["committed_view"] == tx_id.view
        assert body_j["committed_seqno"] == tx_id.seqno
        assert body_j["quote_format"] == "OE_SGX_v1"
        assert body_j["node_id"] == primary.node_id

        r = c.get("/app/api")
        assert r.status_code == HTTPStatus.OK
        openapi_spec_validator.validate_spec(r.body.json())

        r = c.get(f"/app/tx_id?seqno={tx_id.seqno}")
        assert r.status_code == HTTPStatus.OK
        body_j = r.body.json()
        assert body_j["transaction_id"] == f"{tx_id}"

        for i in range(3):
            if i != 0:
                time.sleep(1.5)
            r = c.get("/app/current_time")
            local_time = datetime.now(timezone.utc)
            assert r.status_code == HTTPStatus.OK
            body_j = r.body.json()
            service_time = datetime.fromisoformat(body_j["timestamp"])
            diff = (local_time - service_time).total_seconds()
            # This intends to test that the reported time is "close enough"
            # to the real current time. This is dependent on the skew between
            # clocks on this executor and the target node, and the request
            # latency (including Python IO and parsing). It may need to be
            # more lenient
            assert abs(diff) < 1, diff

        r = c.get("/app/all_nodes")
        assert r.status_code == HTTPStatus.OK
        body_j = r.body.json()
        known_node_ids = [node.node_id for node in (primary, *backups)]
        for node_id, node_info in body_j["nodes"].items():
            assert (
                node_id in known_node_ids
            ), f"Response contains '{node_id}', which is not in known IDs: {known_node_ids}"
            assert node_info["quote_format"] == "OE_SGX_v1"


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        test_nobuiltins_endpoints(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run(args)
