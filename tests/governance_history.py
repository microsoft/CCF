# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import infra.ccf
import infra.proc
import infra.remote
import infra.crypto
import infra.ledger
import json

from loguru import logger as LOG


def count_governance_operations(ledger):
    LOG.debug("Audit the ledger file for governance operations")

    members = {}
    verified_votes = 0
    verified_propose = 0
    verified_withdraw = 0

    for tr in ledger:
        tables = tr.get_public_domain().get_tables()
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
                if "members/vote" in req.decode():
                    verified_votes += 1
                elif "members/propose" in req.decode():
                    verified_propose += 1
                elif "members/withdraw" in req.decode():
                    verified_withdraw += 1

    return (verified_propose, verified_votes, verified_withdraw)


def run(args):
    hosts = ["localhost", "localhost"]

    ledger_filename = None

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, term = network.find_primary()

        ledger_filename = network.find_primary()[0].remote.ledger_path()
        ledger = infra.ledger.Ledger(ledger_filename)
        (
            original_verified_propose,
            original_verified_votes,
            original_verified_withdraw,
        ) = count_governance_operations(ledger)

        LOG.info("Add new member proposal")
        result, error = network.consortium.generate_and_propose_new_member(
            0, primary, new_member_id=3, curve=infra.ccf.ParticipantsCurve.secp256k1
        )
        assert not result["completed"]
        proposal_id = result["id"]

        LOG.debug("2/3 members accept the proposal")
        result = network.consortium.vote(0, primary, proposal_id, True)
        assert result[0] and not result[1]

        LOG.debug("Unsigned votes are rejected")
        result = network.consortium.vote(1, primary, proposal_id, True, True)
        assert (
            not result[0]
            and result[1]["code"] == infra.jsonrpc.ErrorCode.RPC_NOT_SIGNED.value
        )

        result = network.consortium.vote(2, primary, proposal_id, True)
        assert result[0] and result[1]

        LOG.info("Create new proposal but withdraw it before it is accepted")
        result, _ = network.consortium.generate_and_propose_new_member(
            1, primary, new_member_id=4, curve=infra.ccf.ParticipantsCurve.secp256k1
        )
        assert not result["completed"]
        proposal_id = result["id"]

        result = network.consortium.withdraw(1, primary, proposal_id)
        assert result.result

    (
        final_verified_propose,
        final_verified_votes,
        final_verified_withdraw,
    ) = count_governance_operations(ledger)

    assert (
        final_verified_propose == original_verified_propose + 2
    ), f"Unexpected number of propose operations recorded in the ledger ({final_verified_propose})"
    assert (
        final_verified_votes >= original_verified_votes
    ), f"Unexpected number of vote operations recorded in the ledger ({final_verified_votes})"
    assert (
        final_verified_withdraw == original_verified_withdraw + 1
    ), f"Unexpected number of withdraw operations recorded in the ledger ({final_verified_withdraw})"


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    run(args)
