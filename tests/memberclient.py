# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import http

import infra.e2e_args
import infra.network
import infra.consortium
import ccf.proposal_generator
from infra.proposal import ProposalState
import random

import suite.test_requirements as reqs

from loguru import logger as LOG


@reqs.description("Set recovery threshold")
def test_set_recovery_threshold(network, args, recovery_threshold=None):
    if recovery_threshold is None:
        # If the recovery threshold is not specified, a new threshold is
        # randomly selected based on the number of active members. The new
        # recovery threshold is guaranteed to be different from the
        # previous one.
        list_recovery_threshold = list(
            range(1, len(network.consortium.get_active_members()) + 1)
        )
        list_recovery_threshold.remove(network.consortium.recovery_threshold)
        recovery_threshold = random.choice(list_recovery_threshold)

    primary, _ = network.find_primary()
    network.consortium.set_recovery_threshold(primary, recovery_threshold)
    LOG.info(f"Recovery threshold is now {recovery_threshold}")

    return network


@reqs.description("Add a new member to the consortium (+ activation)")
def test_add_member(network, args):
    primary, _ = network.find_primary()

    new_member = network.consortium.generate_and_add_new_member(
        primary, curve=infra.network.ParticipantsCurve(args.participants_curve).next()
    )

    try:
        new_member.get_and_decrypt_recovery_share(
            primary, network.store_current_network_encryption_key()
        )
        assert False, "New accepted members are not given recovery shares"
    except infra.member.NoRecoveryShareFound as e:
        assert e.response.body == "Only active members are given recovery shares"

    new_member.ack(primary)

    return network


@reqs.description("Retire an existing member")
@reqs.sufficient_member_count()
def test_retire_member(network, args, member_to_retire=None):
    primary, _ = network.find_primary()

    if member_to_retire is None:
        member_to_retire = network.consortium.get_any_active_member()
    network.consortium.retire_member(primary, member_to_retire)

    return network


@reqs.description("Issue new recovery shares (without re-key)")
def test_update_recovery_shares(network, args):
    primary, _ = network.find_primary()
    network.consortium.update_recovery_shares(primary)
    return network


@reqs.description("Send an unsigned request where signature is required")
def test_missing_signature(network, args):
    primary, _ = network.find_primary()
    member = network.consortium.get_any_active_member()
    with primary.client(f"member{member.member_id}") as mc:
        r = mc.post("/gov/proposals", signed=False)
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED, r.status_code
        www_auth = "www-authenticate"
        assert www_auth in r.headers, r.headers
        auth_header = r.headers[www_auth]
        assert auth_header.startswith("Signature"), auth_header
        elements = {
            e[0].strip(): e[1]
            for e in (element.split("=") for element in auth_header.split(","))
        }
        assert "headers" in elements, elements
        required_headers = elements["headers"]
        assert required_headers.startswith('"'), required_headers
        assert required_headers.endswith('"'), required_headers
        assert "(request-target)" in required_headers, required_headers
        assert "digest" in required_headers, required_headers

    return network


def assert_recovery_shares_update(func, network, args, **kwargs):
    primary, _ = network.find_primary()

    recovery_threshold_before = network.consortium.recovery_threshold
    active_members_before = network.consortium.get_active_members()
    network.store_current_network_encryption_key()
    already_active_member = network.consortium.get_any_active_member()
    defunct_network_enc_pubk = network.store_current_network_encryption_key()
    saved_share = already_active_member.get_and_decrypt_recovery_share(
        primary, defunct_network_enc_pubk
    )

    if func is test_retire_member:
        # When retiring a member, the active member which retrieved their share
        # should not be retired for them to be able to compare their share afterwards.
        member_to_retire = [
            m
            for m in network.consortium.get_active_members()
            if m is not already_active_member
        ][0]
        func(network, args, member_to_retire)
    elif func is test_set_recovery_threshold and "recovery_threshold" in kwargs:
        func(network, args, recovery_threshold=kwargs["recovery_threshold"])
    else:
        func(network, args)

    if (
        recovery_threshold_before != network.consortium.recovery_threshold
        or active_members_before != network.consortium.get_active_members
    ):
        new_share = already_active_member.get_and_decrypt_recovery_share(
            primary, defunct_network_enc_pubk
        )
        assert saved_share != new_share, "New recovery shares should have been issued"


def run(args):
    hosts = ["localhost"] * (
        4 if args.consensus == "pbft" or args.consensus == "aft" else 2
    )

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        primary, _ = network.find_primary()

        network = test_missing_signature(network, args)

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
            curve=infra.network.ParticipantsCurve(args.participants_curve).next(),
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
        network.consortium.vote_using_majority(primary, new_member_proposal)
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
            .status_code
            == params_error
        )
        assert (
            network.consortium.get_member_by_id(0)
            .vote(primary, new_member_proposal, accept=False)
            .status_code
            == params_error
        )
        assert (
            network.consortium.get_member_by_id(1)
            .vote(primary, new_member_proposal, accept=True)
            .status_code
            == params_error
        )
        assert (
            network.consortium.get_member_by_id(1)
            .vote(primary, new_member_proposal, accept=False)
            .status_code
            == params_error
        )

        LOG.debug("Accepted proposal cannot be withdrawn")
        response = network.consortium.get_member_by_id(
            new_member_proposal.proposer_id
        ).withdraw(primary, new_member_proposal)
        assert response.status_code == params_error

        LOG.info("New non-active member should get insufficient rights response")
        proposal_trust_0, careful_vote = ccf.proposal_generator.trust_node(
            0, vote_against=True
        )
        try:
            new_member.propose(primary, proposal_trust_0, has_proposer_voted_for=False)
            assert (
                False
            ), "New non-active member should get insufficient rights response"
        except infra.proposal.ProposalNotCreated as e:
            assert e.response.status_code == http.HTTPStatus.FORBIDDEN.value

        LOG.debug("New member ACK")
        new_member.ack(primary)

        LOG.info("New member is now active and send an accept node proposal")
        trust_node_proposal_0 = new_member.propose(
            primary, proposal_trust_0, has_proposer_voted_for=False
        )
        trust_node_proposal_0.vote_for = careful_vote

        LOG.debug("Members vote to accept the accept node proposal")
        network.consortium.vote_using_majority(primary, trust_node_proposal_0)
        assert trust_node_proposal_0.state == infra.proposal.ProposalState.Accepted

        LOG.info("New member makes a new proposal, with initial no vote")
        proposal_trust_1, _ = ccf.proposal_generator.trust_node(1)
        trust_node_proposal = new_member.propose(primary, proposal_trust_1)

        LOG.debug("Other members (non proposer) are unable to withdraw new proposal")
        response = network.consortium.get_member_by_id(1).withdraw(
            primary, trust_node_proposal
        )
        assert response.status_code == http.HTTPStatus.FORBIDDEN.value

        LOG.debug("Proposer withdraws their proposal")
        response = new_member.withdraw(primary, trust_node_proposal)
        assert response.status_code == http.HTTPStatus.OK.value
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
        assert response.status_code == params_error

        LOG.debug("Further votes fail")
        response = new_member.vote(primary, trust_node_proposal, accept=True)
        assert response.status_code == params_error

        response = new_member.vote(primary, trust_node_proposal, accept=False)
        assert response.status_code == params_error

        # Membership changes trigger re-sharing and re-keying and are
        # only supported with Raft
        if args.consensus == "raft":
            LOG.debug("New member proposes to retire member 0")
            network.consortium.retire_member(
                primary, network.consortium.get_member_by_id(0)
            )

            LOG.debug("Retired member cannot make a new proposal")
            try:
                response = network.consortium.get_member_by_id(0).propose(
                    primary, proposal_trust_0
                )
                assert False, "Retired member cannot make a new proposal"
            except infra.proposal.ProposalNotCreated as e:
                assert e.response.status_code == http.HTTPStatus.FORBIDDEN.value
                assert e.response.body == "Member is not active"

            LOG.debug("New member should still be able to make a new proposal")
            new_proposal = new_member.propose(primary, proposal_trust_0)
            assert new_proposal.state == ProposalState.Open

            LOG.info(
                "Recovery threshold is originally set to the original number of members"
            )
            LOG.info("Retiring a member should not be possible")
            try:
                assert_recovery_shares_update(test_retire_member, network, args)
                assert False, "Retiring a member should not be possible"
            except infra.proposal.ProposalNotAccepted as e:
                assert e.proposal.state == infra.proposal.ProposalState.Failed

            assert_recovery_shares_update(test_add_member, network, args)
            assert_recovery_shares_update(test_retire_member, network, args)

        LOG.info("Set different recovery thresholds")
        assert_recovery_shares_update(
            test_set_recovery_threshold, network, args, recovery_threshold=1
        )
        test_set_recovery_threshold(
            network, args, recovery_threshold=network.consortium.recovery_threshold,
        )

        LOG.info(
            "Setting the recovery threshold above the number of active members is not possible"
        )
        try:
            test_set_recovery_threshold(
                network,
                args,
                recovery_threshold=len(network.consortium.get_active_members()) + 1,
            )
        except infra.proposal.ProposalNotAccepted as e:
            assert e.proposal.state == infra.proposal.ProposalState.Failed


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
