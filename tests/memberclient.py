# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import sys
import os
import infra.proc

import e2e_args
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
        result = network.consortium.propose(1, primary, None, None, "open_network")
        assert not network.consortium.vote_using_majority(
            primary, result[1]["id"]
        ), "Network should not be opened twice"

        # Create a lua query file to change a member state to accepted
        with open("query.lua", "w") as qfile:
            qfile.write(
                """local tables, param = ...
               local member_id = param
               local STATE_ACCEPTED = 0
               local member_info = {cert = {}, status = STATE_ACCEPTED}
               local p = Puts:new()
               p:put("ccf.members", member_id, member_info)
               return Calls:call("raw_puts", p)"""
            )

        # Create json file to be passed as the argument to the query.lua file
        # It is passing a member id
        with open("param.json", "w") as pfile:
            pfile.write("""{"p": 0}""")

        LOG.info("Proposal to add a new member")
        infra.proc.ccall("./keygenerator", "--name=member4")
        result = network.consortium.propose_add_member(1, primary, "member4_cert.pem")

        # When proposal is added the proposal id and the result of running complete proposal are returned
        proposal_id = result[1]["id"]
        assert not result[1]["completed"]

        # Display all proposals
        proposals = network.consortium.get_proposals(1, primary)

        # Check proposal is present and open
        proposal_entry = proposals.get(str(proposal_id))
        assert proposal_entry
        assert proposal_entry["state"] == "OPEN"

        LOG.debug("2/3 members vote to accept the new member")
        result = network.consortium.vote(1, primary, proposal_id, True)
        assert result[0] and not result[1]

        result = network.consortium.vote(2, primary, proposal_id, True)
        assert result[0] and result[1]

        LOG.debug(
            "Further vote requests fail as the proposal has already been accepted"
        )
        params_error = infra.jsonrpc.ErrorCode.INVALID_PARAMS.value
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
        assert (
            network.consortium.vote(3, primary, proposal_id, True)[1]["code"]
            == params_error
        )
        assert (
            network.consortium.vote(3, primary, proposal_id, False)[1]["code"]
            == params_error
        )

        LOG.debug("Accepted proposal cannot be withdrawn")
        result = network.consortium.withdraw(1, primary, proposal_id)
        assert result["error"]["code"] == params_error

        result = network.consortium.withdraw(2, primary, proposal_id)
        assert (
            result["error"]["code"] == infra.jsonrpc.ErrorCode.INVALID_CALLER_ID.value
        )

        LOG.info("New non-accepted member should get insufficient rights response")
        result = network.consortium.propose(
            4, primary, None, None, "trust_node", "--node-id=0"
        )
        assert result[1]["code"] == infra.jsonrpc.ErrorCode.INSUFFICIENT_RIGHTS.value

        LOG.debug("New member ACK")
        result = network.consortium.ack(4, primary)

        LOG.info("New member is now active and send an accept node proposal")
        result = network.consortium.propose(
            4, primary, None, None, "trust_node", "--node-id=0"
        )
        assert not result[1]["completed"]
        proposal_id = result[1]["id"]

        LOG.debug("Members vote to accept the accept node proposal")
        result = network.consortium.vote(1, primary, proposal_id, True)
        assert result[0] and not result[1]

        # Result is true with 3 votes (proposer, member 1, and member 2)
        result = network.consortium.vote(2, primary, proposal_id, True)
        assert result[0] and result[1]

        LOG.info("New member makes a new proposal")
        result = network.consortium.propose(
            4, primary, None, None, "trust_node", "--node-id=1"
        )
        proposal_id = result[1]["id"]
        assert not result[1]["completed"]

        LOG.debug("Other members (non proposer) are unable to withdraw new proposal")
        result = network.consortium.withdraw(2, primary, proposal_id)
        assert (
            result["error"]["code"] == infra.jsonrpc.ErrorCode.INVALID_CALLER_ID.value
        )

        LOG.debug("Proposer withdraws their proposal")
        result = network.consortium.withdraw(4, primary, proposal_id)
        assert result["result"]

        proposals = network.consortium.get_proposals(4, primary)
        proposal_entry = proposals.get(f"{proposal_id}")
        assert proposal_entry
        assert proposal_entry["state"] == "WITHDRAWN"

        LOG.debug("Further withdraw proposals fail")
        result = network.consortium.withdraw(4, primary, proposal_id)
        assert result["error"]["code"] == params_error

        LOG.debug("Further votes fail")
        result = network.consortium.vote(4, primary, proposal_id, True)
        assert not result[0]
        assert result[1]["code"] == params_error

        result = network.consortium.vote(4, primary, proposal_id, False)
        assert not result[0]
        assert result[1]["code"] == params_error

        LOG.debug("New member proposes to deactivate member 1")
        result = network.consortium.raw_puts(4, primary, "query.lua", "param.json")
        assert not result["result"]["completed"]
        proposal_id = result["result"]["id"]

        LOG.debug("Other members accept the proposal")
        result = network.consortium.vote(3, primary, proposal_id, True)
        assert result[0] and not result[1]

        result = network.consortium.vote(2, primary, proposal_id, True)
        assert result[0] and result[1]

        LOG.debug("Deactivated member cannot make a new proposal")
        result = network.consortium.propose(
            1, primary, None, None, "trust_node", "--node-id=0"
        )
        assert result[1]["code"] == infra.jsonrpc.ErrorCode.INSUFFICIENT_RIGHTS.value

        LOG.debug("New member should still be able to make a new proposal")
        result = network.consortium.propose(
            4, primary, None, None, "add_user", "--user-cert=member3_cert.pem"
        )
        assert not result[1]["completed"]


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., libloggingenc)",
            default="libloggingenc",
        )

    args = e2e_args.cli_args(add)
    run(args)
