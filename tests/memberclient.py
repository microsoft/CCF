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
from infra.proposal_state import ProposalState
import json
import http

from loguru import logger as LOG


def run(args):
    hosts = ["localhost"] * (4 if args.consensus == "pbft" else 2)

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, term = network.find_primary()

        LOG.debug("Original members can ACK")
        result = network.consortium.ack(0, primary)

        LOG.debug("Network should not be able to be opened twice")
        script = """
        tables = ...
        return Calls:call("open_network")
        """
        response = network.consortium.propose(0, primary, script)
        assert response.status == http.HTTPStatus.OK.value

        revote_response = network.consortium.vote_using_majority(
            primary, response.result["proposal_id"]
        )
        assert revote_response.status == http.HTTPStatus.OK.value
        assert revote_response.result["state"] == ProposalState.Failed.value

        # Create a lua query file to change a member state to accepted
        query = """local tables, param = ...
        local member_id = param
        local STATE_ACCEPTED = "ACCEPTED"
        local member_info = {cert = {}, keyshare = {}, status = STATE_ACCEPTED}
        local p = Puts:new()
        p:put("ccf.members", member_id, member_info)
        return Calls:call("raw_puts", p)
        """

        LOG.info("Proposal to add a new member (with different curve)")
        response = network.consortium.generate_and_propose_new_member(
            0,
            primary,
            new_member_id=3,
            curve=infra.ccf.ParticipantsCurve(args.participants_curve).next(),
        )
        assert response.status == http.HTTPStatus.OK.value

        # When proposal is added the proposal id and the result of running complete proposal are returned
        proposal_id = response.result["proposal_id"]
        assert response.result["state"] == ProposalState.Open.value

        # Display all proposals
        proposals = network.consortium.get_proposals(0, primary)

        # Check proposal is present and open
        proposal_entry = proposals.get(str(proposal_id))
        assert proposal_entry
        assert proposal_entry["state"] == ProposalState.Open.value

        LOG.debug("2/3 members vote to accept the new member")
        response = network.consortium.vote(0, primary, proposal_id, True)
        assert response.status == http.HTTPStatus.OK.value
        assert response.result["state"] == ProposalState.Open.value

        response = network.consortium.vote(1, primary, proposal_id, True)
        assert response.status == http.HTTPStatus.OK.value
        assert response.result["state"] == ProposalState.Accepted.value

        LOG.debug(
            "Further vote requests fail as the proposal has already been accepted"
        )
        params_error = http.HTTPStatus.BAD_REQUEST.value
        assert (
            network.consortium.vote(0, primary, proposal_id, True).status
            == params_error
        )
        assert (
            network.consortium.vote(0, primary, proposal_id, False).status
            == params_error
        )
        assert (
            network.consortium.vote(1, primary, proposal_id, True).status
            == params_error
        )
        assert (
            network.consortium.vote(1, primary, proposal_id, False).status
            == params_error
        )
        assert (
            network.consortium.vote(2, primary, proposal_id, True).status
            == params_error
        )
        assert (
            network.consortium.vote(2, primary, proposal_id, False).status
            == params_error
        )

        LOG.debug("Accepted proposal cannot be withdrawn")
        response = network.consortium.withdraw(0, primary, proposal_id)
        assert response.status == params_error

        response = network.consortium.withdraw(1, primary, proposal_id)
        assert response.status == http.HTTPStatus.FORBIDDEN.value

        LOG.info("New non-active member should get insufficient rights response")
        script = """
        tables, node_id = ...
        return Calls:call("trust_node", node_id)
        """
        response = network.consortium.propose(3, primary, script, 0)
        assert response.status == http.HTTPStatus.FORBIDDEN.value

        LOG.debug("New member ACK")
        result = network.consortium.ack(3, primary)

        LOG.info("New member is now active and send an accept node proposal")
        response = network.consortium.propose(3, primary, script, 0)
        assert response.status == http.HTTPStatus.OK.value
        assert response.result["state"] == ProposalState.Open.value
        proposal_id = response.result["proposal_id"]

        LOG.debug("Members vote to accept the accept node proposal")
        response = network.consortium.vote(0, primary, proposal_id, True)
        assert response.status == http.HTTPStatus.OK.value
        assert response.result["state"] == ProposalState.Open.value

        # Result is true with 3 votes (proposer, member 0, and member 1)
        response = network.consortium.vote(1, primary, proposal_id, True)
        assert response.status == http.HTTPStatus.OK.value
        assert response.result["state"] == ProposalState.Accepted.value

        LOG.info("New member makes a new proposal")
        response = network.consortium.propose(3, primary, script, 1)
        assert response.status == http.HTTPStatus.OK.value
        assert response.result["state"] == ProposalState.Open.value
        proposal_id = response.result["proposal_id"]

        LOG.debug("Other members (non proposer) are unable to withdraw new proposal")
        response = network.consortium.withdraw(1, primary, proposal_id)
        assert response.status == http.HTTPStatus.FORBIDDEN.value

        LOG.debug("Proposer withdraws their proposal")
        response = network.consortium.withdraw(3, primary, proposal_id)
        assert response.status == http.HTTPStatus.OK.value
        assert response.result["state"] == ProposalState.Withdrawn.value

        proposals = network.consortium.get_proposals(3, primary)
        proposal_entry = proposals.get(f"{proposal_id}")
        assert proposal_entry
        assert proposal_entry["state"] == "WITHDRAWN"

        LOG.debug("Further withdraw proposals fail")
        response = network.consortium.withdraw(3, primary, proposal_id)
        assert response.status == params_error

        LOG.debug("Further votes fail")
        response = network.consortium.vote(3, primary, proposal_id, True)
        assert response.status == params_error

        response = network.consortium.vote(3, primary, proposal_id, False)
        assert response.status == params_error

        LOG.debug("New member proposes to deactivate member 0")
        response = network.consortium.propose(3, primary, query, 0)
        assert response.status == http.HTTPStatus.OK.value
        assert response.result["state"] == ProposalState.Open.value
        proposal_id = response.result["proposal_id"]

        LOG.debug("Other members accept the proposal")
        response = network.consortium.vote(2, primary, proposal_id, True)
        assert response.status == http.HTTPStatus.OK.value
        assert response.result["state"] == ProposalState.Open.value

        response = network.consortium.vote(1, primary, proposal_id, True)
        assert response.status == http.HTTPStatus.OK.value
        assert response.result["state"] == ProposalState.Accepted.value

        LOG.debug("Deactivated member cannot make a new proposal")
        response = network.consortium.propose(0, primary, script, 0)
        assert response.status == http.HTTPStatus.FORBIDDEN.value

        LOG.debug("New member should still be able to make a new proposal")
        response = network.consortium.propose(3, primary, script, 0)
        assert response.status == http.HTTPStatus.OK.value
        assert response.result["state"] == ProposalState.Open.value


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
