# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import sys
import os
import http

import infra.e2e_args
import infra.ccf
import infra.consortium
from infra.proposal import ProposalState

import suite.test_requirements as reqs
import random

from loguru import logger as LOG


@reqs.description("Set recovery threshold")
def test_set_recovery_threshold(network, args, recovery_threshold=None):
    if recovery_threshold is None:
        # For now, return with no effect. Once this is chained,
        # we should select a random threshold between 1 and the
        # total number of active members
        return

    already_active_member = network.consortium.get_any_active_member()
    saved_share = already_active_member.get_and_decrypt_recovery_share(primary)

    network.consortium.set_recovery_threshold(recovery_threshold)

    # Shares are only updated if the recovery threshold is modified
    if recovery_threshold != network.consortium.recovery_threshold:
        new_share = already_active_member.get_and_decrypt_recovery_share(primary)
        assert (
            saved_share != new_share
        ), "New shares should be issued when the recovery threshold is updated"


@reqs.description("Add a new member to the consortium (+ activation)")
def test_add_member(network, args):
    primary, _ = network.find_primary()

    network.consortium.store_current_network_encryption_key()
    already_active_member = network.consortium.get_any_active_member()
    saved_share = already_active_member.get_and_decrypt_recovery_share(primary)

    new_member = network.consortium.generate_and_add_new_member(
        primary, curve=infra.ccf.ParticipantsCurve(args.participants_curve).next()
    )

    try:
        new_member.get_and_decrypt_recovery_share(primary)
        assert False, "New accepted members are not given recovery shares"
    except infra.member.NoRecoveryShareFound as e:
        assert e.args[0].error == "Member is not active"

    new_member.ack(primary)  # Activate new member

    new_share = already_active_member.get_and_decrypt_recovery_share(primary)
    assert (
        saved_share != new_share
    ), "New shares should be issued when a new member is activated"


@reqs.description("Retire an existing member")
def test_retire_member(network, args):
    primary, _ = network.find_primary()

    network.consortium.store_current_network_encryption_key()
    already_active_member = network.consortium.get_any_active_member()
    saved_share = already_active_member.get_and_decrypt_recovery_share(primary)

    member_to_retire = [
        m
        for m in network.consortium.get_active_members()
        if m is not already_active_member
    ][0]
    network.consortium.retire_member(primary, member_to_retire)

    new_share = already_active_member.get_and_decrypt_recovery_share(primary)
    assert (
        saved_share != new_share
    ), "New shares should be issued when a new member is retired"


def run(args):
    hosts = ["localhost"] * (4 if args.consensus == "pbft" else 2)

    with infra.ccf.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, term = network.find_primary()

        LOG.info("Original members can ACK")
        network.consortium.get_any_active_member().ack(primary)

        LOG.info("Network cannot be opened twice")
        try:
            network.consortium.open_network(primary)
        except infra.proposal.ProposalNotAccepted as e:
            assert e.proposal.state == infra.proposal.ProposalState.Failed

        LOG.info("Proposal to add a new member (with different curve)")
        (
            new_member_proposal,
            new_member,
        ) = network.consortium.generate_and_propose_new_member(
            remote_node=primary,
            curve=infra.ccf.ParticipantsCurve(args.participants_curve).next(),
        )

        LOG.info("Check proposal has been recorded in open state")
        proposals = network.consortium.get_proposals(primary)
        proposal_entry = next(
            (p for p in proposals if p.proposal_id == new_member_proposal.proposal_id),
            None,
        )
        assert proposal_entry
        assert proposal_entry.state == ProposalState.Open

        LOG.info("Rest of consortium accept the proposal")
        response = network.consortium.vote_using_majority(primary, new_member_proposal)
        assert new_member_proposal.state == ProposalState.Accepted

        # Manually add new member to consortium
        network.consortium.members.append(new_member)

        LOG.debug(
            "Further vote requests fail as the proposal has already been accepted"
        )
        params_error = http.HTTPStatus.BAD_REQUEST.value
        assert (
            network.consortium.get_member_by_id(0)
            .vote(primary, new_member_proposal, accept=True)
            .status
            == params_error
        )
        assert (
            network.consortium.get_member_by_id(0)
            .vote(primary, new_member_proposal, accept=False)
            .status
            == params_error
        )
        assert (
            network.consortium.get_member_by_id(1)
            .vote(primary, new_member_proposal, accept=True)
            .status
            == params_error
        )
        assert (
            network.consortium.get_member_by_id(1)
            .vote(primary, new_member_proposal, accept=False)
            .status
            == params_error
        )

        LOG.debug("Accepted proposal cannot be withdrawn")
        response = network.consortium.get_member_by_id(
            new_member_proposal.proposer_id
        ).withdraw(primary, new_member_proposal)
        assert response.status == params_error

        LOG.info("New non-active member should get insufficient rights response")
        script = """
        tables, node_id = ...
        return Calls:call("trust_node", node_id)
        """
        try:
            proposal = new_member.propose(primary, script, 0)
            assert (
                False
            ), "New non-active member should get insufficient rights response"
        except infra.proposal.ProposalNotCreated as e:
            assert e.args[0].status == http.HTTPStatus.FORBIDDEN.value

        LOG.debug("New member ACK")
        new_member.ack(primary)

        LOG.info("New member is now active and send an accept node proposal")
        trust_node_proposal = new_member.propose(primary, script, 0, vote_for=True)

        LOG.debug("Members vote to accept the accept node proposal")
        response = network.consortium.vote_using_majority(primary, trust_node_proposal)
        assert trust_node_proposal.state == infra.proposal.ProposalState.Accepted

        LOG.info("New member makes a new proposal")
        trust_node_proposal = new_member.propose(primary, script, 1)

        LOG.debug("Other members (non proposer) are unable to withdraw new proposal")
        response = network.consortium.get_member_by_id(1).withdraw(
            primary, trust_node_proposal
        )
        assert response.status == http.HTTPStatus.FORBIDDEN.value

        LOG.debug("Proposer withdraws their proposal")
        response = new_member.withdraw(primary, trust_node_proposal)
        assert response.status == http.HTTPStatus.OK.value
        assert trust_node_proposal.state == infra.proposal.ProposalState.Withdrawn

        proposals = network.consortium.get_proposals(primary)
        proposal_entry = next(
            (p for p in proposals if p.proposal_id == trust_node_proposal.proposal_id),
            None,
        )
        assert proposal_entry
        assert proposal_entry.state == ProposalState.Withdrawn

        LOG.debug("Further withdraw proposals fail")
        response = new_member.withdraw(primary, trust_node_proposal)
        assert response.status == params_error

        LOG.debug("Further votes fail")
        response = new_member.vote(primary, trust_node_proposal, accept=True)
        assert response.status == params_error

        response = new_member.vote(primary, trust_node_proposal, accept=False)
        assert response.status == params_error

        LOG.debug("New member proposes to retire member 0")
        network.consortium.retire_member(
            primary, network.consortium.get_member_by_id(0)
        )

        LOG.debug("Retired member cannot make a new proposal")
        try:
            response = network.consortium.get_member_by_id(0).propose(
                primary, script, 0
            )
            assert False, "Retired member cannot make a new proposal"
        except infra.proposal.ProposalNotCreated as e:
            assert e.args[0].status == http.HTTPStatus.FORBIDDEN.value
            assert e.args[0].error == "Member is not active"

        LOG.debug("New member should still be able to make a new proposal")
        new_proposal = new_member.propose(primary, script, 0)
        assert new_proposal.state == ProposalState.Open

        LOG.info(
            "Recovery threshold is originally set to the original number of members"
        )
        LOG.info("Retiring a member should not be possible")
        try:
            test_retire_member(network, args)
        except infra.proposal.ProposalNotAccepted as e:
            assert e.args[0].state == infra.proposal.ProposalState.Failed

        test_add_member(network, args)
        test_retire_member(network, args)

        LOG.info("Set different recovery thresholds")
        network.consortium.set_recovery_threshold(primary, recovery_threshold=1)
        network.consortium.set_recovery_threshold(
            primary, recovery_threshold=network.consortium.recovery_threshold
        )

        LOG.info(
            "Setting the recovery threshold above the number of active members is not possible"
        )
        try:
            resp = network.consortium.set_recovery_threshold(
                primary,
                recovery_threshold=len(network.consortium.get_active_members()) + 1,
            )
        except infra.proposal.ProposalNotAccepted as e:
            assert e.args[0].state == infra.proposal.ProposalState.Failed


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
