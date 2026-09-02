# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import base64
import http
import json
import os

import ccf.ledger
import ccf.read_ledger
import ccf.signatures
import cwt
import infra.crypto
import infra.doc
import infra.logging_app as app
import infra.network
import suite.test_requirements as reqs
from ccf.cose import cert_fingerprint
from ccf.tx_id import TxID
from infra.proposal import ProposalState
from loguru import logger as LOG


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

                    cose_ctx = cwt.COSE.new()
                    cert_pem = cert.decode()
                    cose_key = cwt.COSEKey.from_pem(
                        cert_pem, kid=cert_fingerprint(cert_pem)
                    )
                    phdr, uhdr, payload = cose_ctx.decode_with_headers(
                        base64.b64decode(cose_sign1), cose_key
                    )

                    assert "ccf.gov.msg.type" in phdr
                    msg_type = phdr["ccf.gov.msg.type"]
                    if msg_type == "ballot":
                        op = (
                            phdr["ccf.gov.msg.proposal_id"],
                            member_id.decode(),
                            "vote",
                        )
                    elif msg_type == "withdrawal":
                        op = (
                            phdr["ccf.gov.msg.proposal_id"],
                            member_id.decode(),
                            "withdraw",
                        )
                    elif msg_type == "proposal":
                        (proposal_id,) = tables["public:ccf.gov.proposals"].keys()
                        op = (proposal_id.decode(), member_id.decode(), "propose")
                    else:
                        assert False, (phdr, uhdr, payload)

                    if op in operations:
                        operations.remove(op)

    assert operations == set(), operations


def check_signatures(ledger):
    LOG.debug("Audit the ledger file to confirm signatures schema and positioning")

    prev_sig_txid = None
    for chunk in ledger:
        for tr in chunk:
            tables = tr.get_public_domain().get_tables()
            if not ccf.signatures.is_signature_transaction(tables):
                continue

            gcm_view = tr.gcm_header.view
            gcm_seqno = tr.gcm_header.seqno
            sig_txid = TxID(gcm_view, gcm_seqno)

            raw_table = tables.get(ccf.signatures.SIGNATURE_TX_TABLE_NAME)
            if raw_table is not None:
                payload = ccf.signatures.parse_raw_signature_from_tx(tables)
                assert payload is not None, raw_table
                assert payload.view == gcm_view, (payload, gcm_view)
                assert payload.seqno == gcm_seqno, (payload, gcm_seqno)
                raw_entries = list(raw_table.items())
                assert len(raw_entries) == 1, raw_entries
                raw_sig = json.loads(raw_entries[0][1])
                assert raw_sig["commit_view"] == 0, raw_sig
                assert raw_sig["commit_seqno"] == 0, raw_sig

            if ccf.signatures.COSE_SIGNATURE_TX_TABLE_NAME in tables:
                cose_sign1 = ccf.signatures.parse_cose_signature_from_tx(tables)
                assert cose_sign1 is not None, tables[
                    ccf.signatures.COSE_SIGNATURE_TX_TABLE_NAME
                ]
                msg = cwt.COSEMessage.loads(cose_sign1)
                assert msg.type == cwt.COSETypes.SIGN1, msg
                assert msg.payload is None, msg
                phdr = msg.protected

                KID = 4
                kid = phdr.get(KID)
                assert isinstance(kid, bytes) and len(kid) > 0, phdr

                VDS = 395
                CCF_LEDGER_SHA256 = 2
                assert phdr[VDS] == CCF_LEDGER_SHA256, phdr

                CWT_CLAIMS = 15
                IAT, ISS, SUB = 6, 1, 2
                cwt_claims = phdr[CWT_CLAIMS]
                for label in (IAT, ISS, SUB):
                    assert label in cwt_claims, (label, cwt_claims)

                cose_txid = TxID.from_str(phdr["ccf.v1"]["txid"])
                assert cose_txid.view == gcm_view, (cose_txid, gcm_view)
                assert cose_txid.seqno == gcm_seqno, (cose_txid, gcm_seqno)

            # Adjacent signatures only occur on a view change
            if (
                prev_sig_txid is not None
                and prev_sig_txid.seqno + 1 == sig_txid.seqno
                and sig_txid.view <= prev_sig_txid.view
            ):
                # Reduced from assert while investigating cause
                # https://github.com/microsoft/CCF/issues/5078
                LOG.error(f"Adjacent signatures at {prev_sig_txid} and {sig_txid}")

            prev_sig_txid = sig_txid


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

    public_table_names_in_ledger = {
        tn for tn in table_names_in_ledger if tn.startswith("public:ccf.")
    }
    undocumented_tables = public_table_names_in_ledger - set(table_names)
    assert undocumented_tables == set(), undocumented_tables


def remove_prefix(s, prefix):
    if s.startswith(prefix):
        return s[len(prefix) :]
    return s


@reqs.description("Check tables are documented")
def test_tables_doc(network, args):
    primary, _ = network.find_primary()
    target_seqno = network.create_and_wait_for_ledger_chunk(primary)
    public_state, _ = primary.get_public_state_from_api(target_seqno)
    table_names_in_ledger = public_state.keys()
    check_all_tables_are_documented(
        table_names_in_ledger, "../doc/audit/builtin_maps.rst"
    )
    return network


@reqs.description("Test that all nodes' ledgers can be read")
def test_ledger_is_readable(network, args):
    primary, backups = network.find_nodes()
    target_seqno = network.create_and_wait_for_ledger_chunk(primary)
    for node in (primary, *backups):
        with node.get_ledger_from_api(
            target_seqno,
            local_only=True,
            timeout=args.ledger_recovery_timeout,
        ) as ledger:
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
    target_seqno = network.create_and_wait_for_ledger_chunk()

    primary, backups = network.find_nodes()
    for node in (primary, *backups):
        with node.download_ledger(target_seqno, local_only=True) as ledger_paths:
            assert ccf.read_ledger.run(
                paths=ledger_paths,
                print_mode=ccf.read_ledger.PrintMode.Contents,
                tables_format_rules=format_rule,
            )

    snapshot_dir = network.get_committed_snapshots(primary)
    assert ccf.read_ledger.run(
        paths=[os.path.join(snapshot_dir, os.listdir(snapshot_dir)[-1])],
        print_mode=ccf.read_ledger.PrintMode.Contents,
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
        pdb=args.pdb,
        txs=txs,
    ) as network:
        network.start_and_open(args)
        primary, _ = network.find_primary()

        network.consortium.set_authenticate_session(args.authenticate_session)

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
        assert response.body.json()["proposalState"] == ProposalState.WITHDRAWN.value
        member = network.consortium.get_member_by_local_id(
            new_member_proposal.proposer_id
        )
        governance_operations.add(
            (new_member_proposal.proposal_id, member.service_id, "withdraw")
        )

        target_seqno = network.create_and_wait_for_ledger_chunk(primary)

        with primary.get_ledger_from_api(target_seqno) as ledger:
            check_operations(ledger, governance_operations)
            check_signatures(ledger)

        test_ledger_is_readable(network, args)
        test_read_ledger_utility(network, args)
        test_tables_doc(network, args)
