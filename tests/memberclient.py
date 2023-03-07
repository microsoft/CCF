# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import http
import re

import infra.e2e_args
import infra.network
import infra.consortium
import infra.clients
from infra.proposal import ProposalState

import suite.test_requirements as reqs

from loguru import logger as LOG


@reqs.description("Send an unsigned request where signature is required")
def test_missing_signature_header(network, args):
    node = network.find_node_by_role()
    member = network.consortium.get_any_active_member()
    with node.client(member.local_id) as mc:
        r = mc.post("/gov/proposals")
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED, r.status_code
        www_auth = "www-authenticate"
        assert www_auth in r.headers, r.headers
        auth_header = r.headers[www_auth]
        if auth_header != 'COSE-SIGN1 realm="Signed request access"':
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


def make_signature_corrupter(fn):
    class SignatureCorrupter(infra.clients.HttpSig):
        def auth_flow(self, request):
            yield fn(next(super(SignatureCorrupter, self).auth_flow(request)))

    return SignatureCorrupter


signature_regex = 'signature="([^"]*)"'


def missing_signature(request):
    original = request.headers["authorization"]
    request.headers["authorization"] = re.sub(signature_regex, "", original)
    return request


def empty_signature(request):
    original = request.headers["authorization"]
    request.headers["authorization"] = re.sub(
        signature_regex, 'signature="",', original
    )
    return request


def modified_signature(request):
    original = request.headers["authorization"]
    s = re.search(signature_regex, original).group(1)
    index = len(s) // 3
    char = s[index]
    new_char = "B" if char == "A" else "A"
    new_s = s[:index] + new_char + s[index + 1 :]
    request.headers["authorization"] = re.sub(
        signature_regex, f'signature="{new_s}",', original
    )
    return request


@reqs.description("Send a corrupted signature where signed request is required")
def test_corrupted_signature(network, args):
    node = network.find_node_by_role()

    # Test each supported curve
    for curve in infra.network.EllipticCurve:
        LOG.info(f"Testing curve: {curve.name}")
        # Add a member so we have at least one on this curve
        member = network.consortium.generate_and_add_new_member(
            node,
            curve=curve,
        )

        r = member.ack(node)
        with node.client() as nc:
            nc.wait_for_commit(r)

        with node.client(*member.auth()) as mc:
            # Override the auth provider with invalid ones
            for fn in (missing_signature, empty_signature, modified_signature):
                # pylint: disable=protected-access
                mc.client_impl._auth_provider = make_signature_corrupter(fn)
                r = mc.post("/gov/proposals", '{"actions": []}')
                assert r.status_code == http.HTTPStatus.UNAUTHORIZED, r.status_code

        # Remove the new member once we're done with them
        network.consortium.remove_member(node, member)

    return network


@reqs.description("Test various governance operations")
def test_governance(network, args):
    node = network.find_node_by_role()
    primary, _ = network.find_primary()

    LOG.info("Original members can ACK")
    network.consortium.get_any_active_member().ack(node)

    LOG.info("Network can be opened again, with no effect")
    network.consortium.transition_service_to_open(node)

    LOG.info("Unknown proposal is rejected on completion")

    unkwown_proposal = {"actions": [{"name": "unknown_action"}]}

    try:
        proposal = network.consortium.get_any_active_member().propose(
            primary, unkwown_proposal
        )
        assert False, "Unknown proposal should fail on validation"
    except infra.proposal.ProposalNotCreated:
        pass

    LOG.info("Proposal to add a new member (with different curve)")
    (
        new_member_proposal,
        new_member,
        careful_vote,
    ) = network.consortium.generate_and_propose_new_member(
        remote_node=node,
        curve=infra.network.EllipticCurve(args.participants_curve).next(),
    )

    LOG.info("Check proposal has been recorded in open state")
    with primary.client(network.consortium.get_any_active_member().local_id) as c:
        r = c.get(f"/gov/proposals/{new_member_proposal.proposal_id}")
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] == infra.proposal.ProposalState.OPEN.value

    LOG.info("Rest of consortium accept the proposal")
    network.consortium.vote_using_majority(node, new_member_proposal, careful_vote)
    assert new_member_proposal.state == ProposalState.ACCEPTED

    # Manually add new member to consortium
    network.consortium.members.append(new_member)

    LOG.debug("Further vote requests fail as the proposal has already been accepted")
    params_error = http.HTTPStatus.BAD_REQUEST.value
    assert (
        network.consortium.get_member_by_local_id("member0")
        .vote(node, new_member_proposal, careful_vote)
        .status_code
        == params_error
    )
    assert (
        network.consortium.get_member_by_local_id("member1")
        .vote(node, new_member_proposal, careful_vote)
        .status_code
        == params_error
    )

    LOG.debug("Accepted proposal cannot be withdrawn")
    response = network.consortium.get_member_by_local_id(
        new_member_proposal.proposer_id
    ).withdraw(node, new_member_proposal)
    assert response.status_code == params_error

    LOG.info("New non-active member should get insufficient rights response")
    current_recovery_thresold = network.consortium.recovery_threshold
    try:
        proposal_recovery_threshold, careful_vote = network.consortium.make_proposal(
            "set_recovery_threshold", recovery_threshold=current_recovery_thresold
        )
        new_member.propose(node, proposal_recovery_threshold)
        assert False, "New non-active member should get insufficient rights response"
    except infra.proposal.ProposalNotCreated as e:
        assert e.response.status_code == http.HTTPStatus.FORBIDDEN.value

    LOG.debug("New member ACK")
    new_member.ack(node)

    LOG.info("New member is now active and send a proposal")
    proposal = new_member.propose(node, proposal_recovery_threshold)
    proposal.vote_for = careful_vote

    LOG.debug("Members vote for proposal")
    network.consortium.vote_using_majority(node, proposal, careful_vote)
    assert proposal.state == infra.proposal.ProposalState.ACCEPTED

    LOG.info("New member makes a new proposal")
    proposal_recovery_threshold, careful_vote = network.consortium.make_proposal(
        "set_recovery_threshold", recovery_threshold=current_recovery_thresold
    )
    proposal = new_member.propose(node, proposal_recovery_threshold)

    LOG.debug("Other members (non proposer) are unable to withdraw new proposal")
    response = network.consortium.get_member_by_local_id("member1").withdraw(
        node, proposal
    )
    assert response.status_code == http.HTTPStatus.FORBIDDEN.value

    LOG.debug("Proposer withdraws their proposal")
    response = new_member.withdraw(node, proposal)
    assert response.status_code == http.HTTPStatus.OK.value
    assert proposal.state == infra.proposal.ProposalState.WITHDRAWN

    with primary.client(network.consortium.get_any_active_member().local_id) as c:
        r = c.get(f"/gov/proposals/{proposal.proposal_id}")
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] == infra.proposal.ProposalState.WITHDRAWN.value

    LOG.debug("Further withdraw proposals fail")
    response = new_member.withdraw(node, proposal)
    assert response.status_code == params_error

    LOG.debug("Further votes fail")
    response = new_member.vote(node, proposal, careful_vote)
    assert response.status_code == params_error


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        network = test_missing_signature_header(network, args)
        network = test_corrupted_signature(network, args)
        network = test_governance(network, args)
