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


def run(args):
    hosts = ["localhost", "localhost"]

    ledger_filename = None

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, term = network.find_primary()

        LOG.debug("Propose to add a new member (with a different curve)")
        infra.proc.ccall(
            network.key_generator,
            f"--name=member4",
            "--gen-key-share",
            f"--curve={infra.ccf.ParticipantsCurve.secp256k1.name}",
        )
        result, error = network.consortium.propose_add_member(
            1, primary, "member4_cert.pem", "member4_kshare_pub.pem"
        )

        # When proposal is added the proposal id and the result of running
        # complete proposal are returned
        assert not result["completed"]
        proposal_id = result["id"]

        # 2 out of 3 members vote to accept the new member so that
        # that member can send its own proposals
        LOG.debug("2/3 members accept the proposal")
        result = network.consortium.vote(1, primary, proposal_id, True)
        assert result[0] and not result[1]

        LOG.debug("Failed vote as unsigned")
        result = network.consortium.vote(2, primary, proposal_id, True, True)
        assert (
            not result[0]
            and result[1]["code"] == infra.jsonrpc.ErrorCode.RPC_NOT_SIGNED.value
        )

        result = network.consortium.vote(2, primary, proposal_id, True)
        assert result[0] and result[1]

        ledger_filename = network.find_primary()[0].remote.ledger_path()

    LOG.debug("Audit the ledger file for member votes")
    l = infra.ledger.Ledger(ledger_filename)

    # this maps a member_id to a cert object, and is updated when we iterate the transactions,
    # so that we always have the correct cert for a member on a given transaction
    members = {}
    verified_votes = 0

    for tr in l:
        tables = tr.get_public_domain().get_tables()
        members_table = tables["ccf.member_certs"]
        for cert, member_id in members_table.items():
            members[member_id] = cert

        if "ccf.voting_history" in tables:
            votinghistory_table = tables["ccf.voting_history"]
            for member_id, signed_request in votinghistory_table.items():
                # if the signed vote is stored - there has to be a member at this point
                assert member_id in members
                cert = members[member_id]
                sig = signed_request[0][0]
                req = signed_request[0][1]
                request_body = signed_request[0][2]
                digest = signed_request[0][3]
                infra.crypto.verify_request_sig(cert, sig, req, request_body, digest)
                verified_votes += 1

    assert verified_votes >= 2


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    run(args)
