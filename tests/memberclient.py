# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import sys
import os
import infra.proc

import infra.e2e_args
import getpass
import os
import time
import logging
import multiprocessing
from random import seed
import infra.ccf
import infra.proc
import infra.jsonrpc
import json

from loguru import logger as LOG


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, term = network.find_primary()

        LOG.debug("Network should not be able to be opened twice")
        script = """
        tables = ...
        return Calls:call("open_network")
        """
        result, _ = network.consortium.propose(0, primary, script)
        assert not network.consortium.vote_using_majority(
            primary, result["id"]
        ), "Network should not be opened twice"

        # Create a lua query file to change a member state to accepted
        query = """local tables, param = ...
        local member_id = param
        local STATE_ACCEPTED = 0
        local member_info = {cert = {}, status = STATE_ACCEPTED}
        local p = Puts:new()
        p:put("ccf.members", member_id, member_info)
        return Calls:call("raw_puts", p)
        """

        LOG.info("Proposal to add a new member (with different curve)")
        infra.proc.ccall(
            "./keygenerator.sh",
            "member3",
            infra.ccf.ParticipantsCurve(args.default_curve).next().name,
        )

        script = """
        tables, member_cert = ...
        return Calls:call("new_member", member_cert)
        """
        result, _ = network.consortium.propose_add_member(
            0, primary, "member3_cert.pem"
        )

        # When proposal is added the proposal id and the result of running complete proposal are returned
        proposal_id = result["id"]
        assert not result["completed"]

        # Display all proposals
        proposals = network.consortium.get_proposals(0, primary)

        # Check proposal is present and open
        proposal_entry = proposals.get(str(proposal_id))
        assert proposal_entry
        assert proposal_entry["state"] == "OPEN"

        LOG.debug("2/3 members vote to accept the new member")
        result = network.consortium.vote(0, primary, proposal_id, True)
        assert result[0] and not result[1]

        result = network.consortium.vote(1, primary, proposal_id, True)
        assert result[0] and result[1]

        LOG.debug(
            "Further vote requests fail as the proposal has already been accepted"
        )
        params_error = infra.jsonrpc.ErrorCode.INVALID_PARAMS.value
        assert (
            network.consortium.vote(0, primary, proposal_id, True)[1]["code"]
            == params_error
        )
        assert (
            network.consortium.vote(0, primary, proposal_id, False)[1]["code"]
            == params_error
        )
        assert (
            network.consortium.vote(1, primary, proposal_id, True)[1]["code"]
            == params_error
        )
        assert (
            network.consortium.vote(1, primary, proposal_id, False)[1]["code"]
            == params_error
        )
        assert (
            network.consortium.vote(2, primary, proposal_id, True)[1]["code"]
            == params_error
        )
        assert (
            network.consortium.vote(2, primary, proposal_id, False)[1]["code"]
            == params_error
        )

        LOG.debug("Accepted proposal cannot be withdrawn")
        result = network.consortium.withdraw(0, primary, proposal_id)
        assert result.error["code"] == params_error

        result = network.consortium.withdraw(1, primary, proposal_id)
        assert result.error["code"] == infra.jsonrpc.ErrorCode.INVALID_CALLER_ID.value

        LOG.info("New non-active member should get insufficient rights response")
        script = """
        tables, node_id = ...
        return Calls:call("trust_node", node_id)
        """
        result, error = network.consortium.propose(3, primary, script, 0)
        assert error["code"] == infra.jsonrpc.ErrorCode.INSUFFICIENT_RIGHTS.value

        LOG.debug("New member ACK")
        result = network.consortium.ack(3, primary)

        LOG.info("New member is now active and send an accept node proposal")
        result, _ = network.consortium.propose(3, primary, script, 0)
        assert not result["completed"]
        proposal_id = result["id"]

        LOG.debug("Members vote to accept the accept node proposal")
        result = network.consortium.vote(0, primary, proposal_id, True)
        assert result[0] and not result[1]

        # Result is true with 3 votes (proposer, member 0, and member 1)
        result = network.consortium.vote(1, primary, proposal_id, True)
        assert result[0] and result[1]

        LOG.info("New member makes a new proposal")
        result, _ = network.consortium.propose(3, primary, script, 1)
        proposal_id = result["id"]
        assert not result["completed"]

        LOG.debug("Other members (non proposer) are unable to withdraw new proposal")
        result = network.consortium.withdraw(1, primary, proposal_id)
        assert result.error["code"] == infra.jsonrpc.ErrorCode.INVALID_CALLER_ID.value

        LOG.debug("Proposer withdraws their proposal")
        result = network.consortium.withdraw(3, primary, proposal_id)
        assert result.result

        proposals = network.consortium.get_proposals(3, primary)
        proposal_entry = proposals.get(f"{proposal_id}")
        assert proposal_entry
        assert proposal_entry["state"] == "WITHDRAWN"

        LOG.debug("Further withdraw proposals fail")
        result = network.consortium.withdraw(3, primary, proposal_id)
        assert result.error["code"] == params_error

        LOG.debug("Further votes fail")
        result = network.consortium.vote(3, primary, proposal_id, True)
        assert not result[0]
        assert result[1]["code"] == params_error

        result = network.consortium.vote(3, primary, proposal_id, False)
        assert not result[0]
        assert result[1]["code"] == params_error

        LOG.debug("New member proposes to deactivate member 0")
        result, _ = network.consortium.propose(3, primary, query, 0)
        assert not result["completed"]
        proposal_id = result["id"]

        LOG.debug("Other members accept the proposal")
        result = network.consortium.vote(2, primary, proposal_id, True)
        assert result[0] and not result[1]

        result = network.consortium.vote(1, primary, proposal_id, True)
        assert result[0] and result[1]

        LOG.debug("Deactivated member cannot make a new proposal")
        result, error = network.consortium.propose(0, primary, script, 0)
        assert error["code"] == infra.jsonrpc.ErrorCode.INSUFFICIENT_RIGHTS.value

        LOG.debug("New member should still be able to make a new proposal")
        result, _ = network.consortium.propose(3, primary, script, 0)
        assert not result["completed"]


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., liblogging)",
            default="liblogging",
        )

    args = infra.e2e_args.cli_args(add)
    run(args)
