# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import sys
import http
import subprocess
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs
import infra.logging_app as app
import json
import urllib.parse

from loguru import logger as LOG


@reqs.description("Test quotes")
@reqs.supports_methods("quotes/self", "quotes")
def test_quote(network, args):
    primary, _ = network.find_nodes()
    with primary.client() as c:
        oed = subprocess.run(
            [
                os.path.join(args.oe_binary, "oesign"),
                "dump",
                "-e",
                infra.path.build_lib_path(args.package, args.enclave_type),
            ],
            capture_output=True,
            check=True,
        )
        lines = [
            line
            for line in oed.stdout.decode().split(os.linesep)
            if line.startswith("mrenclave=")
        ]
        expected_mrenclave = lines[0].strip().split("=")[1]

        r = c.get("/node/quotes/self")
        primary_quote_info = r.body.json()
        assert primary_quote_info["node_id"] == 0
        primary_mrenclave = primary_quote_info["mrenclave"]
        assert primary_mrenclave == expected_mrenclave, (
            primary_mrenclave,
            expected_mrenclave,
        )

        r = c.get("/node/quotes")
        quotes = r.body.json()["quotes"]
        assert len(quotes) == len(network.get_joined_nodes())

        for quote in quotes:
            mrenclave = quote["mrenclave"]
            assert mrenclave == expected_mrenclave, (mrenclave, expected_mrenclave)
            quote_path = os.path.join(network.common_dir, f"quote{quote['node_id']}")
            endorsements_path = os.path.join(
                network.common_dir, f"endorsements{quote['node_id']}"
            )

            with open(quote_path, "wb") as q:
                q.write(bytes.fromhex(quote["raw"]))

            with open(endorsements_path, "wb") as e:
                e.write(bytes.fromhex(quote["endorsements"]))

            cafile = os.path.join(network.common_dir, "networkcert.pem")
            assert (
                infra.proc.ccall(
                    "verify_quote.sh",
                    f"https://{primary.pubhost}:{primary.pubport}",
                    "--cacert",
                    f"{cafile}",
                    log_output=True,
                ).returncode
                == 0
            ), f"Quote verification for node {quote['node_id']} failed"

    return network


@reqs.description("Add user, remove user")
@reqs.supports_methods("log/private")
def test_user(network, args, verify=True):
    # Note: This test should not be chained in the test suite as it creates
    # a new user and uses its own LoggingTxs
    primary, _ = network.find_nodes()
    new_user_id = 3
    network.create_users([new_user_id], args.participants_curve)
    user_data = {"lifetime": "temporary"}
    network.consortium.add_user(primary, new_user_id, user_data)
    txs = app.LoggingTxs(user_id=new_user_id)
    txs.issue(
        network=network,
        number_txs=1,
    )
    if verify:
        txs.verify()
    network.consortium.remove_user(primary, new_user_id)
    with primary.client(f"user{new_user_id}") as c:
        r = c.get("/app/log/private")
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED.value
    return network


@reqs.description("Add untrusted node, check no quote is returned")
def test_no_quote(network, args):
    untrusted_node = network.create_and_add_pending_node(
        args.package, "local://localhost", args
    )
    with untrusted_node.client(
        ca=os.path.join(untrusted_node.common_dir, f"{untrusted_node.node_id}.pem")
    ) as uc:
        r = uc.get("/node/quotes/self")
        assert r.status_code == http.HTTPStatus.NOT_FOUND
    return network


@reqs.description("Check member data")
def test_member_data(network, args):
    assert args.initial_operator_count > 0
    primary, _ = network.find_nodes()
    with primary.client("member0") as mc:

        def member_info(mid):
            return mc.post(
                "/gov/read", {"table": "public:ccf.gov.members.info", "key": mid}
            ).body.json()

        md_count = 0
        for member in network.get_members():
            if member.member_data:
                assert (
                    member_info(member.member_id)["member_data"] == member.member_data
                )
                md_count += 1
            else:
                assert "member_data" not in member_info(member.member_id)
        assert md_count == args.initial_operator_count

    return network


@reqs.description("Check caller_id")
def test_caller_id(network, args):
    primary, _ = network.find_nodes()
    with primary.client("user0") as uc:
        with open(network.consortium.user_cert_path(1), "r") as ucert:
            pem = ucert.read()
        json_pem = json.dumps(pem)
        r = uc.get(f"/app/caller_id?cert={urllib.parse.quote_plus(json_pem)}")
        assert r.status_code == http.HTTPStatus.OK.value
        assert r.body.json()["caller_id"] == 1
    return network


@reqs.description("Check network/nodes endpoint")
def test_node_ids(network, args):
    nodes = network.find_nodes()
    for node in nodes:
        with node.client() as c:
            r = c.get(
                f'/node/network/nodes?host="{node.pubhost}"&port="{node.pubport}"'
            )
            assert r.status_code == http.HTTPStatus.OK.value
            info = r.body.json()["nodes"]
            assert len(info) == 1
            assert info[0]["node_id"] == node.node_id
            assert info[0]["status"] == "TRUSTED"
        return network


@reqs.description("Checking service principals proposals")
def test_service_principals(network, args):
    primary, _ = network.find_nodes()

    principal_id = "0xdeadbeef"
    ballot = {"ballot": {"text": "return true"}}

    def read_service_principal():
        with primary.client("member0") as mc:
            return mc.post(
                "/gov/read",
                {"table": "public:gov.service_principals", "key": principal_id},
            )

    # Initially, there is nothing in this table
    r = read_service_principal()
    assert r.status_code == http.HTTPStatus.NOT_FOUND.value

    # Create and accept a proposal which populates an entry in this table
    principal_data = {"name": "Bob", "roles": ["Fireman", "Zookeeper"]}
    proposal = {
        "script": {
            "text": 'tables, args = ...\nreturn Calls:call("set_service_principal", args)'
        },
        "parameter": {
            "id": principal_id,
            "data": principal_data,
        },
    }
    proposal = network.consortium.get_any_active_member().propose(primary, proposal)
    network.consortium.vote_using_majority(primary, proposal, ballot)

    # Confirm it can be read
    r = read_service_principal()
    assert r.status_code == http.HTTPStatus.OK.value
    j = r.body.json()
    assert j == principal_data

    # Create and accept a proposal which removes an entry from this table
    proposal = {
        "script": {
            "text": 'tables, args = ...\nreturn Calls:call("remove_service_principal", args)'
        },
        "parameter": {
            "id": principal_id,
        },
    }
    proposal = network.consortium.get_any_active_member().propose(primary, proposal)
    network.consortium.vote_using_majority(primary, proposal, ballot)

    # Confirm it is gone
    r = read_service_principal()
    assert r.status_code == http.HTTPStatus.NOT_FOUND.value

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_node_ids(network, args)
        network = test_member_data(network, args)
        network = test_quote(network, args)
        network = test_user(network, args)
        network = test_no_quote(network, args)
        network = test_caller_id(network, args)
        network = test_service_principals(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    if args.enclave_type == "virtual":
        LOG.warning("This test can only run in real enclaves, skipping")
        sys.exit(0)

    args.package = "liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.initial_user_count = 3
    run(args)
