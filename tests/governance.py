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
from infra.node import NodeStatus
import infra.e2e_args
import suite.test_requirements as reqs
import infra.logging_app as app
import json

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
        assert primary_quote_info["node_id"] == primary.node_id
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
    new_user_local_id = f"user{3}"
    new_user = network.create_user(new_user_local_id, args.participants_curve)
    user_data = {"lifetime": "temporary"}
    network.consortium.add_user(primary, new_user.local_id, user_data)
    txs = app.LoggingTxs(user_id=new_user.local_id)
    txs.issue(
        network=network,
        number_txs=1,
    )
    if verify:
        txs.verify()
    network.consortium.remove_user(primary, new_user.service_id)
    with primary.client(new_user_local_id) as c:
        r = c.get("/app/log/private")
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED.value
    return network


@reqs.description("Add untrusted node, check no quote is returned")
def test_no_quote(network, args):
    untrusted_node = network.create_and_add_pending_node(
        args.package, "local://localhost", args
    )
    with untrusted_node.client(
        ca=os.path.join(untrusted_node.common_dir, f"{untrusted_node.local_id}.pem")
    ) as uc:
        r = uc.get("/node/quotes/self")
        assert r.status_code == http.HTTPStatus.NOT_FOUND
    return network


@reqs.description("Check member data")
def test_member_data(network, args):
    assert args.initial_operator_count > 0
    primary, _ = network.find_nodes()

    latest_public_tables, _ = primary.get_latest_ledger_public_state()
    members_info = latest_public_tables["public:ccf.gov.members.info"]

    md_count = 0
    for member in network.get_members():
        stored_member_info = json.loads(members_info[member.service_id.encode()])
        if member.member_data:
            assert (
                stored_member_info["member_data"] == member.member_data
            ), f'stored member data "{stored_member_info["member_data"]}" != expected "{member.member_data} "'
            md_count += 1
        else:
            assert "member_data" not in stored_member_info

    assert md_count == args.initial_operator_count

    return network


@reqs.description("Check network/nodes endpoint")
def test_node_ids(network, args):
    nodes = network.find_nodes()
    for node in nodes:
        with node.client() as c:
            r = c.get(f"/node/network/nodes?host={node.pubhost}&port={node.pubport}")
            assert r.status_code == http.HTTPStatus.OK.value
            info = r.body.json()["nodes"]
            assert len(info) == 1
            assert info[0]["node_id"] == node.node_id
            assert info[0]["status"] == NodeStatus.TRUSTED.value
        return network


@reqs.description("Checking service principals proposals")
def test_service_principals(network, args):
    node = network.find_node_by_role()

    principal_id = "0xdeadbeef"

    # Initially, there is nothing in this table
    latest_public_tables, _ = node.get_latest_ledger_public_state()
    assert "public:ccf.gov.service_principals" not in latest_public_tables

    # Create and accept a proposal which populates an entry in this table
    principal_data = {"name": "Bob", "roles": ["Fireman", "Zookeeper"]}
    if os.getenv("JS_GOVERNANCE"):
        proposal = {
            "actions": [
                {
                    "name": "set_service_principal",
                    "args": {"id": principal_id, "data": principal_data},
                }
            ]
        }
        ballot = {
            "ballot": "export function vote(proposal, proposer_id) { return true; }"
        }
    else:
        proposal = {
            "script": {
                "text": 'tables, args = ...\nreturn Calls:call("set_service_principal", args)'
            },
            "parameter": {
                "id": principal_id,
                "data": principal_data,
            },
        }
        ballot = {"ballot": {"text": "return true"}}
    proposal = network.consortium.get_any_active_member().propose(node, proposal)
    network.consortium.vote_using_majority(node, proposal, ballot)

    # Confirm it can be read
    latest_public_tables, _ = node.get_latest_ledger_public_state()
    assert (
        json.loads(
            latest_public_tables["public:ccf.gov.service_principals"][
                principal_id.encode()
            ]
        )
        == principal_data
    )

    # Create and accept a proposal which removes an entry from this table
    if os.getenv("JS_GOVERNANCE"):
        proposal = {
            "actions": [
                {"name": "remove_service_principal", "args": {"id": principal_id}}
            ]
        }
    else:
        proposal = {
            "script": {
                "text": 'tables, args = ...\nreturn Calls:call("remove_service_principal", args)'
            },
            "parameter": {
                "id": principal_id,
            },
        }
    proposal = network.consortium.get_any_active_member().propose(node, proposal)
    network.consortium.vote_using_majority(node, proposal, ballot)

    # Confirm it is gone
    latest_public_tables, _ = node.get_latest_ledger_public_state()
    assert (
        principal_id.encode()
        not in latest_public_tables["public:ccf.gov.service_principals"]
    )
    return network


@reqs.description("Test ack state digest updates")
def test_ack_state_digest_update(network, args):
    for node in network.get_joined_nodes():
        network.consortium.get_any_active_member().update_ack_state_digest(node)


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
        network = test_service_principals(network, args)
        network = test_ack_state_digest_update(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    if args.enclave_type == "virtual":
        LOG.warning("This test can only run in real enclaves, skipping")
        sys.exit(0)

    args.package = "liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.initial_user_count = 3
    run(args)
