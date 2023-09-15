# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
from loguru import logger as LOG
import suite.test_requirements as reqs

API_VERSION = "2023-06-01-preview"
API_VERSION_QUERY = f"api-version={API_VERSION}"


@reqs.description("Check that TypeSpec-defined service_state interface is available")
def test_api_service_state(network, args):
    primary, _ = network.find_primary()

    with primary.client() as c:
        # Test members endpoints
        r = c.get(f"/gov/service/members?{API_VERSION_QUERY}")
        assert r.status_code == 200, r
        body = r.body.json()
        member_infos = {}
        for member in body["value"]:
            assert member["status"] == "Active", member
            assert member["certificate"].startswith(
                "-----BEGIN CERTIFICATE-----"
            ), member
            member_infos[member["memberId"]] = member

        for member_id, member_info in member_infos.items():
            r = c.get(f"/gov/service/members/{member_id}?{API_VERSION_QUERY}")
            assert r.status_code == 200, r
            body = r.body.json()
            assert body == member_info

        # Test nodes endpoints
        r = c.get(f"/gov/service/nodes?{API_VERSION_QUERY}")
        assert r.status_code == 200, r
        body = r.body.json()
        node_infos = {}
        for node in body["value"]:
            assert node["status"] == "Trusted", node
            assert node["certificate"].startswith(
                "-----BEGIN CERTIFICATE-----"
            ), node
            assert node["retiredCommitted"] == False, node
            node_infos[node["nodeId"]] = node

        for node_id, node_info in node_infos.items():
            r = c.get(f"/gov/service/nodes/{node_id}?{API_VERSION_QUERY}")
            assert r.status_code == 200, r
            body = r.body.json()
            assert body == node_info

    return network


@reqs.description("Check that TypeSpec-defined transactions interface is available")
def test_api_transactions(network, args):
    primary, _ = network.find_primary()

    with primary.client() as c:
        r = c.get(f"/gov/service/transactions/commit?{API_VERSION_QUERY}")
        assert r.status_code == 200, r
        info = r.body.json()
        assert info["status"] == "Committed", r
        tx_id = info["transactionId"]

        r = c.get(f"/gov/service/transactions/{tx_id}?{API_VERSION_QUERY}")
        assert r.status_code == 200, r
        info = r.body.json()
        assert info["status"] == "Committed", r
        assert info["transactionId"] == tx_id, r

    return network


def run(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)

        network = test_api_service_state(network, args)
        network = test_api_transactions(network, args)
