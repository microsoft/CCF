# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import suite.test_requirements as reqs
import infra.clients


@reqs.description("Check that TypeSpec-defined service_state interface is available")
def test_api_service_state(network, args):
    primary, _ = network.find_primary()

    with primary.api_versioned_client(api_version=args.gov_api_version) as c:
        # Test members endpoints
        r = c.get("/gov/service/members")
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
            r = c.get(f"/gov/service/members/{member_id}")
            assert r.status_code == 200, r
            body = r.body.json()
            assert body == member_info

        # Test nodes endpoints
        r = c.get("/gov/service/nodes")
        assert r.status_code == 200, r
        body = r.body.json()
        node_infos = {}
        for node in body["value"]:
            assert node["status"] == "Trusted", node
            assert node["certificate"].startswith("-----BEGIN CERTIFICATE-----"), node
            assert node["retiredCommitted"] is False, node
            node_infos[node["nodeId"]] = node

        for node_id, node_info in node_infos.items():
            r = c.get(f"/gov/service/nodes/{node_id}")
            assert r.status_code == 200, r
            body = r.body.json()
            assert body == node_info

    return network


@reqs.description("Check that TypeSpec-defined transactions interface is available")
def test_api_transactions(network, args):
    primary, _ = network.find_primary()

    with primary.api_versioned_client(api_version=args.gov_api_version) as c:
        r = c.get("/gov/service/transactions/commit")
        assert r.status_code == 200, r
        info = r.body.json()
        assert info["status"] == "Committed", r
        tx_id = info["transactionId"]

        r = c.get(f"/gov/service/transactions/{tx_id}")
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
