# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.ccf
import infra.proc
import infra.remote
import infra.crypto
import infra.ledger
from infra.proposal import ProposalState
import json
import http

from loguru import logger as LOG


def count_governance_operations(ledger):
    LOG.debug("Audit the ledger file for governance operations")

    members = {}
    verified_votes = 0
    verified_proposals = 0
    verified_withdrawals = 0

    for tr in ledger:
        tables = tr.get_public_domain().get_tables()
        if "ccf.member_certs" in tables:
            members_table = tables["ccf.member_certs"]
            for cert, member_id in members_table.items():
                members[member_id] = cert

        if "ccf.governance.history" in tables:
            governance_history_table = tables["ccf.governance.history"]
            for member_id, signed_request in governance_history_table.items():
                assert member_id in members
                cert = members[member_id]
                sig = signed_request[0][0]
                req = signed_request[0][1]
                request_body = signed_request[0][2]
                digest = signed_request[0][3]
                infra.crypto.verify_request_sig(cert, sig, req, request_body, digest)
                if "members/propose" in req.decode():
                    verified_proposals += 1
                elif "members/vote" in req.decode():
                    verified_votes += 1
                elif "members/withdraw" in req.decode():
                    verified_withdrawals += 1

    return (verified_proposals, verified_votes, verified_withdrawals)


def run(args):
    hosts = ["localhost", "localhost"]

    # Keep track of how many propose, vote and withdraw are issued in this test
    proposals_issued = 0
    votes_issued = 0
    withdrawals_issued = 0

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, term = network.find_primary()

        ledger_filename = network.find_primary()[0].remote.ledger_path()
        ledger = infra.ledger.Ledger(ledger_filename)
        (
            original_proposals,
            original_votes,
            original_withdrawals,
        ) = count_governance_operations(ledger)

        LOG.info("Add new member proposal (implicit vote)")
        (
            new_member_proposal,
            new_member,
        ) = network.consortium.generate_and_propose_new_member(
            primary, curve=infra.ccf.ParticipantsCurve.secp256k1
        )
        proposals_issued += 1

        LOG.info("2/3 members accept the proposal")
        response = network.consortium.vote_using_majority(primary, new_member_proposal)
        votes_issued += 1
        assert response.status == http.HTTPStatus.OK.value
        assert response.result["state"] == ProposalState.Accepted.value

        LOG.info("Unsigned votes are rejected")
        response = network.consortium.get_member_by_id(2).vote(
            primary, new_member_proposal, accept=True, force_unsigned=True
        )
        assert response.status == http.HTTPStatus.UNAUTHORIZED.value

        LOG.info("Create new proposal but withdraw it before it is accepted")
        (
            new_member_proposal,
            new_member,
        ) = network.consortium.generate_and_propose_new_member(
            primary, curve=infra.ccf.ParticipantsCurve.secp256k1
        )
        proposals_issued += 1

        response = network.consortium.get_member_by_id(
            new_member_proposal.proposer_id
        ).withdraw(primary, new_member_proposal)
        assert response.status == http.HTTPStatus.OK.value
        assert response.result["state"] == ProposalState.Withdrawn.value
        withdrawals_issued += 1

    (final_proposals, final_votes, final_withdrawals,) = count_governance_operations(
        ledger
    )

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
    run(args)
