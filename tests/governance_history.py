# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import infra.remote
import infra.crypto
import ccf.ledger
import infra.doc
from infra.proposal import ProposalState
import http
import base64
import json
from loguru import logger as LOG
import suite.test_requirements as reqs
import ccf.read_ledger
import infra.logging_app as app


def check_operations(ledger, operations):
    LOG.debug("Audit the ledger file for governance operations")

    members = {}
    for chunk in ledger:
        for tr in chunk:
            tables = tr.get_public_domain().get_tables()
            if "public:ccf.gov.members.certs" in tables:
                members_table = tables["public:ccf.gov.members.certs"]
                for member_id, member_cert in members_table.items():
                    members[member_id] = member_cert

            if "public:ccf.gov.history" in tables:
                governance_history_table = tables["public:ccf.gov.history"]
                for member_id, signed_request in governance_history_table.items():
                    assert member_id in members
                    signed_request = json.loads(signed_request)

                    cert = members[member_id]
                    sig = base64.b64decode(signed_request["sig"])
                    req = base64.b64decode(signed_request["req"])
                    request_body = base64.b64decode(signed_request["request_body"])
                    digest = signed_request["md"]

                    infra.crypto.verify_request_sig(
                        cert, sig, req, request_body, digest
                    )
                    request_target_line = req.decode().splitlines()[0]
                    if "/gov/proposals" in request_target_line:
                        vote_suffix = "/ballots"
                        elements = request_target_line.split("/")
                        if request_target_line.endswith(vote_suffix):
                            op = (elements[-2], member_id.decode(), "vote")
                        elif request_target_line.endswith("/withdraw"):
                            op = (elements[-2], member_id.decode(), "withdraw")
                        else:
                            (proposal_id,) = tables["public:ccf.gov.proposals"].keys()
                            op = (proposal_id.decode(), member_id.decode(), "propose")

                        if op in operations:
                            operations.remove(op)

    assert operations == set(), operations


def check_all_tables_are_documented(ledger, doc_path):
    with open(doc_path) as doc:
        parsed_doc = infra.doc.parse(doc.read())
        table_names = infra.doc.extract_table_names(parsed_doc)

    table_names_in_ledger = set()
    for chunk in ledger:
        for tr in chunk:
            table_names_in_ledger.update(tr.get_public_domain().get_tables().keys())

    public_table_names_in_ledger = set(
        [tn for tn in table_names_in_ledger if tn.startswith("public:ccf.")]
    )
    undocumented_tables = public_table_names_in_ledger - set(table_names)
    assert undocumented_tables == set(), undocumented_tables


@reqs.description("Check tables are documented")
def test_tables_doc(network, args):
    primary, _ = network.find_primary()
    ledger_directories = primary.remote.ledger_paths()
    ledger = ccf.ledger.Ledger(ledger_directories)
    check_all_tables_are_documented(ledger, "../doc/audit/builtin_maps.rst")
    return network


@reqs.description("Test that all nodes' ledgers can be read")
def test_ledger_is_readable(network, args):
    primary, backups = network.find_nodes()
    for node in (primary, *backups):
        ledger_dirs = node.remote.ledger_paths()
        LOG.info(f"Reading ledger from {ledger_dirs}")
        ledger = ccf.ledger.Ledger(ledger_dirs)
        for chunk in ledger:
            for _ in chunk:
                pass
    return network


@reqs.description("Test that all nodes' ledgers can be read using read_ledger.py")
def test_read_ledger_utility(network, args):
    def fmt_str(data: bytes) -> str:
        return data.decode()

    format_rule = [(".*records.*", {"key": fmt_str, "value": fmt_str})]

    # Issue at least one transaction to see how it is read in the ledger
    network.txs.issue(network, number_txs=1)
    network.get_latest_ledger_public_state()

    primary, backups = network.find_nodes()
    for node in (primary, *backups):
        ledger_dirs = node.remote.ledger_paths()
        assert ccf.read_ledger.run(ledger_dirs, tables_format_rules=format_rule)
    return network


def run(args):
    # Keep track of governance operations that happened in the test
    governance_operations = set()

    txs = app.LoggingTxs("user0")
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_join(args)
        primary, _ = network.find_primary()

        ledger_directories = primary.remote.ledger_paths()
        LOG.info("Add new member proposal (implicit vote)")
        (
            new_member_proposal,
            _,
            careful_vote,
        ) = network.consortium.generate_and_propose_new_member(
            primary, curve=infra.network.EllipticCurve.secp256r1
        )
        member = network.consortium.get_member_by_local_id(
            new_member_proposal.proposer_id
        )
        governance_operations.add(
            (new_member_proposal.proposal_id, member.service_id, "propose")
        )

        LOG.info("2/3 members accept the proposal")
        p = network.consortium.vote_using_majority(
            primary, new_member_proposal, careful_vote
        )
        for voter in p.voters:
            governance_operations.add((p.proposal_id, voter, "vote"))
        assert new_member_proposal.state == infra.proposal.ProposalState.ACCEPTED

        LOG.info("Create new proposal but withdraw it before it is accepted")
        new_member_proposal, _, _ = network.consortium.generate_and_propose_new_member(
            primary, curve=infra.network.EllipticCurve.secp256r1
        )
        member = network.consortium.get_member_by_local_id(
            new_member_proposal.proposer_id
        )
        governance_operations.add(
            (new_member_proposal.proposal_id, member.service_id, "propose")
        )

        with primary.client() as c:
            response = network.consortium.get_member_by_local_id(
                new_member_proposal.proposer_id
            ).withdraw(primary, new_member_proposal)
            infra.checker.Checker(c)(response)
        assert response.status_code == http.HTTPStatus.OK.value
        assert response.body.json()["state"] == ProposalState.WITHDRAWN.value
        member = network.consortium.get_member_by_local_id(
            new_member_proposal.proposer_id
        )
        governance_operations.add(
            (new_member_proposal.proposal_id, member.service_id, "withdraw")
        )

        # Force ledger flush of all transactions so far
        network.get_latest_ledger_public_state()
        ledger = ccf.ledger.Ledger(ledger_directories)
        check_operations(ledger, governance_operations)

        test_ledger_is_readable(network, args)
        test_read_ledger_utility(network, args)
        test_tables_doc(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    run(args)
