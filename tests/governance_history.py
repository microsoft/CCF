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
import os
import base64
import json
from loguru import logger as LOG
import suite.test_requirements as reqs
import ccf.read_ledger
import infra.logging_app as app
import infra.signing


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

            if "public:ccf.gov.cose_history" in tables:
                cose_history_table = tables["public:ccf.gov.cose_history"]
                for member_id, cose_sign1 in cose_history_table.items():
                    assert member_id in members
                    cert = members[member_id]

                    msg = infra.signing.verify_cose_sign1(
                        base64.b64decode(cose_sign1), cert.decode()
                    )
                    assert "ccf.gov.msg.type" in msg.phdr
                    msg_type = msg.phdr["ccf.gov.msg.type"]
                    if msg_type == "ballot":
                        op = (
                            msg.phdr["ccf.gov.msg.proposal_id"],
                            member_id.decode(),
                            "vote",
                        )
                    elif msg_type == "withdrawal":
                        op = (
                            msg.phdr["ccf.gov.msg.proposal_id"],
                            member_id.decode(),
                            "withdraw",
                        )
                    elif msg_type == "proposal":
                        (proposal_id,) = tables["public:ccf.gov.proposals"].keys()
                        op = (proposal_id.decode(), member_id.decode(), "propose")
                    else:
                        assert False, msg

                    if op in operations:
                        operations.remove(op)

            signatures_table_name = "public:ccf.internal.signatures"
            if signatures_table_name in tables:
                signatures_table = tables[signatures_table_name]
                signatures = list(signatures_table.items())
                assert len(signatures) == 1, signatures
                signature_raw = signatures[0][1]
                signature = json.loads(signature_raw)
                # commit_view and commit_seqno fields are unsigned, deprecated, and set to 0
                assert signature["commit_view"] == 0, signature
                assert signature["commit_seqno"] == 0, signature
                # view and seqno fields are unsigned, and always match the txID contained in the GcmHeader
                assert tr.gcm_header.view == signature["view"]
                assert tr.gcm_header.seqno == signature["seqno"]

    assert operations == set(), operations


def check_all_tables_are_documented(table_names_in_ledger, doc_path):
    # Check that all CCF tables present in the input ledger are documented.
    # Tables marked as experimental in the doc must not be present in the ledger.
    with open(doc_path, encoding="utf-8") as doc:
        parsed_doc = infra.doc.parse(doc.read())
        table_names = infra.doc.extract_table_names(parsed_doc)

    experimental_table_names = [tn for tn in table_names if "(experimental)" in tn]
    table_names = [tn for tn in table_names if tn not in experimental_table_names]
    experimental_table_names = [tn.split(" ")[0] for tn in experimental_table_names]

    experimental_table_names_in_ledger = [
        tn for tn in table_names_in_ledger if tn in experimental_table_names
    ]
    if experimental_table_names_in_ledger:
        raise ValueError(
            f"Experimental tables {experimental_table_names_in_ledger} were present in ledger"
        )

    public_table_names_in_ledger = set(
        [tn for tn in table_names_in_ledger if tn.startswith("public:ccf.")]
    )
    undocumented_tables = public_table_names_in_ledger - set(table_names)
    assert undocumented_tables == set(), undocumented_tables


def remove_prefix(s, prefix):
    if s.startswith(prefix):
        return s[len(prefix) :]
    return s


def check_all_tables_have_wrapper_endpoints(table_names, node):
    gov_prefix = "public:ccf.gov."
    missing = []
    with node.client() as c:
        for table_name in table_names:
            if table_name.startswith(gov_prefix):
                LOG.info(f"Testing {table_name}")
                uri = table_name[len(gov_prefix) :]
                uri = uri.replace(".", "/")
                r = c.get(f"/gov/kv/{uri}")
                if r.status_code != http.HTTPStatus.OK:
                    missing.append(table_name)

    assert (
        len(missing) == 0
    ), f"Missing endpoints to access the following tables: {missing}"


@reqs.description("Check tables are documented and wrapped")
def test_tables_doc(network, args):
    primary, _ = network.find_primary()
    ledger_directories = primary.remote.ledger_paths()
    ledger = ccf.ledger.Ledger(ledger_directories)
    table_names_in_ledger = ledger.get_latest_public_state()[0].keys()
    check_all_tables_are_documented(
        table_names_in_ledger, "../doc/audit/builtin_maps.rst"
    )
    check_all_tables_have_wrapper_endpoints(table_names_in_ledger, primary)
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

    network.txs.issue(network, number_txs=args.snapshot_tx_interval)
    network.get_latest_ledger_public_state()

    primary, backups = network.find_nodes()
    for node in (primary, *backups):
        ledger_dirs = node.remote.ledger_paths()
        assert ccf.read_ledger.run(paths=ledger_dirs, tables_format_rules=format_rule)

    snapshot_dir = network.get_committed_snapshots(primary)
    assert ccf.read_ledger.run(
        paths=[os.path.join(snapshot_dir, os.listdir(snapshot_dir)[-1])],
        is_snapshot=True,
        tables_format_rules=format_rule,
    )
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
        network.start_and_open(args)
        primary, _ = network.find_primary()

        network.consortium.set_authenticate_session(args.authenticate_session)

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
