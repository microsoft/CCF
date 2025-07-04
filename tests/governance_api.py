# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import suite.test_requirements as reqs
import infra.clients

from loguru import logger as LOG  # type: ignore


@reqs.description("Check that TypeSpec-defined service_state interface is available")
def test_api_service_state(network, args):
    primary, _ = network.find_primary()

    with primary.api_versioned_client(api_version=args.gov_api_version) as c:
        LOG.info("/gov/service/members* endpoints")
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

        LOG.info("/gov/service/users* endpoints")
        r = c.get("/gov/service/users")
        assert r.status_code == 200, r
        body = r.body.json()
        user_infos = {}
        for user in body["value"]:
            assert user["certificate"].startswith("-----BEGIN CERTIFICATE-----"), user
            user_infos[user["userId"]] = user

        for user_id, user_info in user_infos.items():
            r = c.get(f"/gov/service/users/{user_id}")
            assert r.status_code == 200, r
            body = r.body.json()
            assert body == user_info

        LOG.info("/gov/service/nodes* endpoints")
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

        LOG.info(
            "Sanity check - these ID namespaces are distinct, and the endpoints return sensible 404s"
        )
        member_id = next(iter(member_infos.keys()))
        user_id = next(iter(user_infos.keys()))
        node_id = next(iter(node_infos.keys()))

        for uri in [
            # /gov/service/members/{id}
            f"/gov/service/members/{user_id}",
            f"/gov/service/members/{node_id}",
            # /gov/service/users/{id}
            f"/gov/service/users/{member_id}",
            f"/gov/service/users/{node_id}",
            # /gov/service/nodes/{id}
            f"/gov/service/nodes/{user_id}",
            f"/gov/service/nodes/{member_id}",
        ]:
            r = c.get(uri)
            assert r.status_code == 404, r

        LOG.info("Confirm that all expected values were returned")
        local_members = network.consortium.members
        assert len(local_members) == len(member_infos)
        for local_member in local_members:
            assert local_member.service_id in member_infos
            member_info = member_infos[local_member.service_id]
            assert local_member.cert == member_info["certificate"]

        local_users = network.users
        assert len(local_users) == len(user_infos)
        for local_user in local_users:
            assert local_user.service_id in user_infos
            user_info = user_infos[local_user.service_id]
            local_cert = open(local_user.cert_path).read()
            assert local_cert == user_info["certificate"]

        local_nodes = network.nodes
        assert len(local_nodes) == len(node_infos)
        for local_node in local_nodes:
            assert local_node.node_id in node_infos

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
