# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.network
import infra.proc
import infra.remote
import infra.crypto
import ccf.ledger
from infra.proposal import ProposalState
import http
import base64
import json
from loguru import logger as LOG


def count_governance_operations(ledger):
    LOG.debug("Audit the ledger file for governance operations")

    members = {}
    verified_votes = 0
    verified_proposals = 0
    verified_withdrawals = 0

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
                        if request_target_line.endswith("/votes"):
                            verified_votes += 1
                        elif request_target_line.endswith("/withdraw"):
                            verified_withdrawals += 1
                        else:
                            verified_proposals += 1

    return (verified_proposals, verified_votes, verified_withdrawals)


def run(args):
    # Keep track of how many propose, vote and withdraw are issued in this test
    proposals_issued = 0
    votes_issued = 0
    withdrawals_issued = 0

    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, _ = network.find_primary()

        ledger_directory = primary.remote.ledger_path()

        ledger = ccf.ledger.Ledger(ledger_directory)
        (
            original_proposals,
            original_votes,
            original_withdrawals,
        ) = count_governance_operations(ledger)

        LOG.info("Add new member proposal (implicit vote)")
        (
            new_member_proposal,
            _,
            careful_vote,
        ) = network.consortium.generate_and_propose_new_member(
            primary, curve=infra.network.ParticipantsCurve.secp256r1
        )
        proposals_issued += 1

        LOG.info("2/3 members accept the proposal")
        p = network.consortium.vote_using_majority(
            primary, new_member_proposal, careful_vote
        )
        votes_issued += p.votes_for
        assert new_member_proposal.state == infra.proposal.ProposalState.ACCEPTED

        LOG.info("Create new proposal but withdraw it before it is accepted")
        new_member_proposal, _, _ = network.consortium.generate_and_propose_new_member(
            primary, curve=infra.network.ParticipantsCurve.secp256r1
        )
        proposals_issued += 1

        with primary.client() as c:
            response = network.consortium.get_member_by_local_id(
                new_member_proposal.proposer_id
            ).withdraw(primary, new_member_proposal)
            infra.checker.Checker(c)(response)
        assert response.status_code == http.HTTPStatus.OK.value
        assert response.body.json()["state"] == ProposalState.WITHDRAWN.value
        withdrawals_issued += 1

    # Refresh ledger to beginning
    ledger = ccf.ledger.Ledger(ledger_directory)

    (
        final_proposals,
        final_votes,
        final_withdrawals,
    ) = count_governance_operations(ledger)

    assert (
        final_proposals == original_proposals + proposals_issued
    ), f"Unexpected number of propose operations recorded in the ledger (expected {original_proposals + proposals_issued}, found {final_proposals})"
    assert (
        final_votes == original_votes + votes_issued
    ), f"Unexpected number of vote operations recorded in the ledger (expected {original_votes + votes_issued}, found {final_votes})"
    assert (
        final_withdrawals == original_withdrawals + withdrawals_issued
    ), f"Unexpected number of withdraw operations recorded in the ledger (expected {original_withdrawals + withdrawals_issued}, found {final_withdrawals})"


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    run(args)
