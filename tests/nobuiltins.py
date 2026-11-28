# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from http import HTTPStatus

import infra.platform_detection
import openapi_spec_validator
from ccf.tx_id import TxID


def test_nobuiltins_endpoints(network, args):
    primary, backups = network.find_nodes()
    with primary.client() as c:
        r = c.get("/commit")
        assert r.status_code == HTTPStatus.OK
        body_j = r.body.json()
        tx_id = TxID.from_str(body_j["transaction_id"])

        r = c.get("/app/node_summary")
        assert r.status_code == HTTPStatus.OK
        body_j = r.body.json()
        assert body_j["committed_view"] >= tx_id.view
        assert body_j["committed_seqno"] >= tx_id.seqno
        if infra.platform_detection.is_virtual():
            expected_format = "Insecure_Virtual"
        elif infra.platform_detection.is_snp():
            expected_format = "AMD_SEV_SNP_v1"
        else:
            raise ValueError(
                f"Unhandled enclave platform = {infra.platform_detection.get_platform()}"
            )
        assert body_j["quote_format"] == expected_format, body_j["quote_format"]
        assert body_j["node_id"] == primary.node_id

        r = c.get("/app/api")
        assert r.status_code == HTTPStatus.OK
        openapi_spec_validator.validate_spec(r.body.json())

        r = c.get(f"/app/tx_id?seqno={tx_id.seqno}")
        assert r.status_code == HTTPStatus.OK
        body_j = r.body.json()
        assert body_j["transaction_id"] == f"{tx_id}"

        r = c.get("/app/all_nodes")
        assert r.status_code == HTTPStatus.OK
        body_j = r.body.json()
        known_node_ids = [node.node_id for node in (primary, *backups)]
        for node_id, node_info in body_j["nodes"].items():
            assert (
                node_id in known_node_ids
            ), f"Response contains '{node_id}', which is not in known IDs: {known_node_ids}"
            assert node_info["quote_format"] == expected_format, node_info[
                "quote_format"
            ]
