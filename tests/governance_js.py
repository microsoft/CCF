# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import infra.proposal
import infra.member
import suite.test_requirements as reqs
import os
from loguru import logger as LOG
from contextlib import contextmanager
import dataclasses
import tempfile
import uuid
import infra.clients
import json
import ccf.ledger


def action(name, **args):
    return {"name": name, "args": args}


def proposal(*actions):
    return {"actions": list(actions)}


def merge(*proposals):
    return {"actions": sum((prop["actions"] for prop in proposals), [])}


def vote(body):
    return {"ballot": f"export function vote (proposal, proposer_id) {{ {body} }}"}


valid_set_recovery_threshold = proposal(
    action("set_recovery_threshold", recovery_threshold=5)
)
valid_set_recovery_threshold_twice = merge(
    valid_set_recovery_threshold, valid_set_recovery_threshold
)
always_accept_noop = proposal(action("always_accept_noop"))
always_reject_noop = proposal(action("always_reject_noop"))
always_accept_with_one_vote = proposal(action("always_accept_with_one_vote"))
always_reject_with_one_vote = proposal(action("always_reject_with_one_vote"))
always_accept_if_voted_by_operator = proposal(
    action("always_accept_if_voted_by_operator")
)
always_accept_if_proposed_by_operator = proposal(
    action("always_accept_if_proposed_by_operator")
)
always_accept_with_two_votes = proposal(action("always_accept_with_two_votes"))
always_reject_with_two_votes = proposal(action("always_reject_with_two_votes"))
check_proposal_id_is_set_correctly = proposal(
    action("check_proposal_id_is_set_correctly")
)

ballot_yes = vote("return true")
ballot_no = vote("return false")


def unique_always_accept_noop():
    return proposal(action("always_accept_noop", uuid=str(uuid.uuid4())))


def set_service_recent_cose_proposals_window_size(proposal_count):
    return proposal(
        action(
            "set_service_recent_cose_proposals_window_size",
            proposal_count=proposal_count,
        )
    )


def choose_node(network):
    # Ideally, this would use find_random_node - you should be able to use any
    # node for governance.
    # However, many of these tests include a pattern of
    #   POST /proposal
    #   GET /proposal
    # If the former request is redirected, then the latter may fail (essentially
    # reading stale state, assuming session consistency that doesn't exist).
    # return network.find_random_node()

    # Instead we ensure that all requests go to the primary
    primary, _ = network.find_primary()
    return primary


@reqs.description("Test COSE msg type validation")
def test_cose_msg_type_validation(network, args):
    node = choose_node(network)

    with node.api_versioned_client(
        None, None, "member0", api_version=args.gov_api_version
    ) as c:

        def check_msg_type(verb, path, name, auth_policy):
            r = c.call(
                path,
                b"{ not valid json",
                http_verb=verb,
                cose_header_parameters_override={"ccf.gov.msg.type": "incorrect"},
            )
            assert r.status_code == 401
            expected_error = {
                "auth_policy": auth_policy,
                "code": "InvalidAuthenticationInfo",
                "message": f"Found ccf.gov.msg.type set to incorrect, expected ccf.gov.msg.type to be {name}",
            }
            assert expected_error in r.body.json()["error"]["details"], r.body.json()[
                "error"
            ]["details"]

        proposal = os.urandom(32).hex()
        member = os.urandom(32).hex()
        member_auth = "member_cose_sign1"
        active_member_auth = "active_member_cose_sign1"
        to_be_checked = [
            ("POST", "/gov/members/proposals:create", "proposal", active_member_auth),
            (
                "POST",
                f"/gov/members/proposals/{proposal}:withdraw",
                "withdrawal",
                active_member_auth,
            ),
            (
                "POST",
                f"/gov/members/proposals/{proposal}/ballots/{member}:submit",
                "ballot",
                active_member_auth,
            ),
            ("POST", f"/gov/members/state-digests/{member}:ack", "ack", member_auth),
            (
                "POST",
                f"/gov/members/state-digests/{member}:update",
                "state_digest",
                member_auth,
            ),
        ]

        for verb, path, name, auth_policy in to_be_checked:
            check_msg_type(verb, path, name, auth_policy)


@reqs.description("Test proposal validation")
def test_proposal_validation(network, args):
    node = choose_node(network)

    def assert_invalid_proposal(proposal_body):
        try:
            member.propose(node, proposal_body)
        except infra.proposal.ProposalNotCreated as e:
            r = e.response
            assert (
                r.status_code == 400
                and r.body.json()["error"]["code"] == "ProposalFailedToValidate"
            ), r.body.text()

    def assert_malformed_proposal(proposal_body):
        try:
            member.propose(node, proposal_body)
        except infra.proposal.ProposalNotCreated as e:
            r = e.response
            assert (
                r.status_code == 500
                and r.body.json()["error"]["code"] == "InternalError"
                and r.body.json()["error"]["message"].startswith(
                    "Failed to execute validation: SyntaxError:"
                )
            ), r.body.text()

    member = network.consortium.get_any_active_member()

    # Non-JSON body
    assert_malformed_proposal(b"{ not valid json")

    # Incorrect arg type
    assert_invalid_proposal(proposal(action("valid_pem", pem="That's not a PEM")))

    # Successfully validated
    with open(
        os.path.join(network.common_dir, "service_cert.pem"), "r", encoding="utf-8"
    ) as cert:
        valid_pem = cert.read()
        member.propose(node, proposal(action("valid_pem", pem=valid_pem)))

    # Arg missing
    assert_invalid_proposal(proposal(action("remove_user")))

    # Not a string
    assert_invalid_proposal(proposal(action("remove_user", user_id=42)))

    # Too short
    assert_invalid_proposal(proposal(action("remove_user", user_id="deadbeef")))

    # Too long
    assert_invalid_proposal(
        proposal(
            action(
                "remove_user",
                user_id="0deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            )
        )
    )

    # Not hex
    assert_invalid_proposal(
        proposal(
            action(
                "remove_user",
                user_id="totboeuftotboeuftotboeuftotboeuftotboeuftotboeuftotboeuftotboeuf",
            )
        )
    )

    # Just right
    # NB: It validates (structurally correct type), but does nothing because this user doesn't exist
    member.propose(
        node,
        proposal(
            action(
                "remove_user",
                user_id="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            )
        ),
    )

    return network


@reqs.description("Test proposal storage")
def test_proposal_storage(network, args):
    node = choose_node(network)

    plausible = os.urandom(32).hex()

    with node.api_versioned_client(
        None, None, "member0", api_version=args.gov_api_version
    ) as c:
        r = c.get(f"/gov/members/proposals/{plausible}")
        assert r.status_code == 404, r.body.text()

        r = c.get(f"/gov/members/proposals/{plausible}/actions")
        assert r.status_code == 404, r.body.text()

        for prop in (valid_set_recovery_threshold, valid_set_recovery_threshold_twice):
            r = c.post("/gov/members/proposals:create", prop)
            assert r.status_code == 200, r.body.text()
            proposal_id = r.body.json()["proposalId"]

            r = c.get(f"/gov/members/proposals/{proposal_id}")
            assert r.status_code == 200, r.body.text()
            proposer_id = network.consortium.get_member_by_local_id(
                "member0"
            ).service_id
            expected = {
                "proposerId": proposer_id,
                "proposalState": "Open",
                "proposalId": proposal_id,
                "ballotCount": 0,
            }
            assert r.body.json() == expected, r.body.json()

            r = c.get(f"/gov/members/proposals/{proposal_id}/actions")
            assert r.status_code == 200, r.body.text()
            assert r.body.json() == prop, r.body.json()

    return network


@reqs.description("Test proposal withdrawal")
def test_proposal_withdrawal(network, args):
    node = choose_node(network)
    infra.clients.get_clock().advance()

    plausible = os.urandom(32).hex()

    with node.api_versioned_client(
        None, None, "member0", api_version=args.gov_api_version
    ) as c:
        for prop in (valid_set_recovery_threshold, valid_set_recovery_threshold_twice):
            r = c.post(f"/gov/members/proposals/{plausible}:withdraw")
            # Idempotent - we don't know if this used to exist
            assert r.status_code == 204, r.body.text()

            r = c.post("/gov/members/proposals:create", prop)
            assert r.status_code == 200, r.body.text()
            proposal_id = r.body.json()["proposalId"]

            with node.api_versioned_client(
                None, None, "member1", api_version=args.gov_api_version
            ) as oc:
                r = oc.post(f"/gov/members/proposals/{proposal_id}:withdraw")
                assert r.status_code == 403, r.body.text()

            r = c.get(f"/gov/members/proposals/{proposal_id}")
            assert r.status_code == 200, r.body.text()
            proposer_id = network.consortium.get_member_by_local_id(
                "member0"
            ).service_id
            expected = {
                "proposerId": proposer_id,
                "proposalState": "Open",
                "proposalId": proposal_id,
                "ballotCount": 0,
            }
            assert r.body.json() == expected, r.body.json()

            r = c.post(f"/gov/members/proposals/{proposal_id}:withdraw")
            assert r.status_code == 200, r.body.text()
            expected = {
                "proposerId": proposer_id,
                "proposalState": "Withdrawn",
                "proposalId": proposal_id,
                "ballotCount": 0,
            }
            assert r.body.json() == expected, r.body.json()

            r = c.post(f"/gov/members/proposals/{proposal_id}:withdraw")
            # Idempotent - sure we'll try to withdraw this again
            assert r.status_code == 200, r.body.text()

    return network


@reqs.description("Test ballot storage and validation")
def test_ballot_storage(network, args):
    node = choose_node(network)

    infra.clients.get_clock().advance()

    with node.api_versioned_client(
        None, None, "member0", api_version=args.gov_api_version
    ) as c:
        member_id = network.consortium.get_member_by_local_id("member0").service_id
        r = c.post("/gov/members/proposals:create", valid_set_recovery_threshold)
        assert r.status_code == 200, r.body.text()
        proposal_id = r.body.json()["proposalId"]

        r = c.post(
            f"/gov/members/proposals/{proposal_id}/ballots/{member_id}:submit", {}
        )
        assert r.status_code == 400, r.body.text()

        ballot = ballot_yes
        r = c.post(
            f"/gov/members/proposals/{proposal_id}/ballots/{member_id}:submit", ballot
        )
        assert r.status_code == 200, r.body.text()

        r = c.post(
            f"/gov/members/proposals/{proposal_id}/ballots/{member_id}:submit", ballot
        )
        # Idempotence - resubmission is fine
        assert r.status_code == 200, r.body.text()

        # Changing ballot is not allowed
        r = c.post(
            f"/gov/members/proposals/{proposal_id}/ballots/{member_id}:submit",
            ballot_no,
        )
        assert r.status_code == 400, r.body.text()
        assert r.body.json()["error"]["code"] == "VoteAlreadyExists", r.body.json()

        r = c.get(f"/gov/members/proposals/{proposal_id}/ballots/{member_id}")
        assert r.status_code == 200, r.body.text()
        assert r.headers["content-type"] == "text/javascript"
        assert r.body.text() == ballot["ballot"], r.body.text()

    with node.api_versioned_client(
        None, None, "member1", api_version=args.gov_api_version
    ) as c:
        member_id = network.consortium.get_member_by_local_id("member1").service_id

        ballot = ballot_no
        r = c.post(
            f"/gov/members/proposals/{proposal_id}/ballots/{member_id}:submit", ballot
        )
        assert r.status_code == 200, r.body.text()

        r = c.get(f"/gov/members/proposals/{proposal_id}/ballots/{member_id}")
        assert r.status_code == 200, r.body.text()
        assert r.headers["content-type"] == "text/javascript"
        assert r.body.text() == ballot["ballot"]

    return network


@reqs.description("Test pure proposals")
def test_pure_proposals(network, args):
    node = choose_node(network)

    with node.api_versioned_client(
        None, None, "member0", api_version=args.gov_api_version
    ) as c:
        for prop, state in [
            (always_accept_noop, "Accepted"),
            (always_reject_noop, "Rejected"),
        ]:
            member_id = network.consortium.get_member_by_local_id("member0").service_id

            r = c.post("/gov/members/proposals:create", prop)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["proposalState"] == state, r.body.json()
            proposal_id = r.body.json()["proposalId"]

            ballot = ballot_yes
            r = c.post(
                f"/gov/members/proposals/{proposal_id}/ballots/{member_id}:submit",
                ballot,
            )
            assert r.status_code == 400, r.body.text()

            r = c.post(f"/gov/members/proposals/{proposal_id}:withdraw")
            assert r.status_code == 400, r.body.text()

    return network


@reqs.description("Test proposal replay protection")
def test_proposal_replay_protection(network, args):
    node = choose_node(network)

    with node.api_versioned_client(
        None, None, "member0", api_version=args.gov_api_version
    ) as c:
        # Creating a proposal with too large a created_at always fails
        c.set_created_at_override(int("1" + "0" * 10))
        r = c.post("/gov/members/proposals:create", always_accept_noop)
        assert (
            r.status_code == 400
            and r.body.json()["error"]["code"] == "InvalidCreatedAt"
        ), r.body.text()

        infra.clients.get_clock().advance()
        # Fill window size with proposals
        window_size = 100
        now = infra.clients.get_clock()
        submitted = []
        for i in range(window_size):
            c.set_created_at_override((now + i).moment())
            proposal = unique_always_accept_noop()
            r = c.post("/gov/members/proposals:create", proposal)
            assert r.status_code == 200, r.body.text()
            submitted.append(proposal)

        # Re-submitting the last proposal is detected as a replay
        last_index = window_size - 1
        c.set_created_at_override((now + last_index).moment())
        r = c.repeat_last_request()
        assert (
            r.status_code == 400 and r.body.json()["error"]["code"] == "ProposalReplay"
        ), r.body.text()

        # Submitting proposals earlier than, or in the first half of the window is rejected
        c.set_created_at_override((now - 1).moment())
        r = c.post("/gov/members/proposals:create", always_accept_noop)
        assert (
            r.status_code == 400
            and r.body.json()["error"]["code"] == "ProposalCreatedTooLongAgo"
        ), r.body.text()

        c.set_created_at_override((now + (window_size // 2 - 1)).moment())
        r = c.post("/gov/members/proposals:create", always_accept_noop)
        assert (
            r.status_code == 400
            and r.body.json()["error"]["code"] == "ProposalCreatedTooLongAgo"
        ), r.body.text()

        # Submitting a unique proposal just past the median of the window does work
        c.set_created_at_override((now + (window_size // 2)).moment())
        r = c.post("/gov/members/proposals:create", unique_always_accept_noop())
        assert r.status_code == 200, r.body.text()

        r = c.post(
            "/gov/members/proposals:create",
            set_service_recent_cose_proposals_window_size(1),
        )
        assert r.status_code == 200, r.body.text()

        # Submitting a new unique proposal works
        c.set_created_at_override((now + window_size).moment())
        r = c.post("/gov/members/proposals:create", unique_always_accept_noop())
        assert r.status_code == 200, r.body.text()

        # Submitting a unique proposal just prior to that no longer does
        c.set_created_at_override((now + window_size - 2).moment())
        r = c.post("/gov/members/proposals:create", unique_always_accept_noop())
        assert (
            r.status_code == 400
            and r.body.json()["error"]["code"] == "ProposalCreatedTooLongAgo"
        ), r.body.text()

    return network


@reqs.description("Test open proposals")
def test_all_open_proposals(network, args):
    node = choose_node(network)
    with node.api_versioned_client(
        None, None, "member0", api_version=args.gov_api_version
    ) as c:
        r = c.post("/gov/members/proposals:create", always_accept_noop)
        assert r.status_code == 200, r.body.text()
        first = r.body.json()
        assert first["proposalState"] == "Accepted", r.body.json()

        r = c.get("/gov/members/proposals")
        assert r.status_code == 200, r.body.text()
        proposals = r.body.json()["value"]
        assert len(proposals) == 1, proposals
        # Response at passing time might contain more detail. This later summary is a subset of the earlier object
        assert proposals[0].items() <= first.items(), proposals

        r = c.post("/gov/members/proposals:create", always_accept_with_one_vote)
        assert r.status_code == 200, r.body.text()
        second = r.body.json()
        assert second["proposalState"] == "Open", second

        r = c.get("/gov/members/proposals")
        assert r.status_code == 200, r.body.text()
        proposals = r.body.json()["value"]
        assert len(proposals) == 2, proposals
        for proposal in proposals:
            if proposal["proposalId"] == first["proposalId"]:
                assert proposal.items() <= first.items(), proposal
            elif proposal["proposalId"] == second["proposalId"]:
                assert proposal.items() <= second.items(), proposal
            else:
                assert False, proposal

    return network


def opposite(js_bool):
    if js_bool == "true":
        return "false"
    elif js_bool == "false":
        return "true"
    else:
        raise ValueError(f"{js_bool} is not a JavaScript boolean")


@reqs.description("Test vote proposals")
def test_proposals_with_votes(network, args):
    node = choose_node(network)
    with node.api_versioned_client(
        None, None, "member0", api_version=args.gov_api_version
    ) as c:
        member_id = network.consortium.get_member_by_local_id("member0").service_id

        for prop, state, direction in [
            (always_accept_with_one_vote, "Accepted", "true"),
            (always_reject_with_one_vote, "Rejected", "false"),
        ]:
            r = c.post("/gov/members/proposals:create", prop)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["proposalState"] == "Open", r.body.json()
            proposal_id = r.body.json()["proposalId"]

            ballot = vote(f"return {direction}")
            r = c.post(
                f"/gov/members/proposals/{proposal_id}/ballots/{member_id}:submit",
                ballot,
            )
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["proposalState"] == state, r.body.json()

            infra.clients.get_clock().advance()

            r = c.post("/gov/members/proposals:create", prop)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["proposalState"] == "Open", r.body.json()
            proposal_id = r.body.json()["proposalId"]

            ballot = vote(
                f'if (proposer_id == "{member_id}") {{ return {direction} }} else {{ return {opposite(direction) } }}'
            )
            r = c.post(
                f"/gov/members/proposals/{proposal_id}/ballots/{member_id}:submit",
                ballot,
            )
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["proposalState"] == state, r.body.json()

        for prop, state, ballot in [
            (always_accept_with_two_votes, "Accepted", ballot_yes),
            (always_reject_with_two_votes, "Rejected", ballot_no),
        ]:
            r = c.post("/gov/members/proposals:create", prop)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["proposalState"] == "Open", r.body.json()
            proposal_id = r.body.json()["proposalId"]

            r = c.post(
                f"/gov/members/proposals/{proposal_id}/ballots/{member_id}:submit",
                ballot,
            )
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["proposalState"] == "Open", r.body.json()

            with node.api_versioned_client(
                None, None, "member1", api_version=args.gov_api_version
            ) as oc:
                other_member_id = network.consortium.get_member_by_local_id(
                    "member1"
                ).service_id
                r = oc.post(
                    f"/gov/members/proposals/{proposal_id}/ballots/{other_member_id}:submit",
                    ballot,
                )
                assert r.status_code == 200, r.body.text()
                assert r.body.json()["proposalState"] == state, r.body.json()

    return network


@reqs.description("Test proposal id is set correctly in resolve()")
def test_check_proposal_id_is_set_correctly(network, args):
    node = choose_node(network)
    with node.api_versioned_client(
        None, None, "member0", api_version=args.gov_api_version
    ) as c:
        r = c.post("/gov/members/proposals:create", check_proposal_id_is_set_correctly)
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["proposalState"] == "Accepted", r.body.json()

    return network


@reqs.description("Test vote failure reporting")
def test_vote_failure_reporting(network, args):
    node = choose_node(network)

    error_body = f"Sample error ({uuid.uuid4()})"

    with node.api_versioned_client(
        None, None, "member0", api_version=args.gov_api_version
    ) as c:
        member_id = network.consortium.get_member_by_local_id("member0").service_id
        r = c.post("/gov/members/proposals:create", always_accept_with_one_vote)
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["proposalState"] == "Open", r.body.json()
        proposal_id = r.body.json()["proposalId"]

        ballot = vote(f'throw new Error("{error_body}")')
        r = c.post(
            f"/gov/members/proposals/{proposal_id}/ballots/{member_id}:submit", ballot
        )
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["proposalState"] == "Open", r.body.json()

    with node.api_versioned_client(
        None, None, "member1", api_version=args.gov_api_version
    ) as c:
        ballot = ballot_yes
        member_id = network.consortium.get_member_by_local_id("member1").service_id
        r = c.post(
            f"/gov/members/proposals/{proposal_id}/ballots/{member_id}:submit", ballot
        )
        assert r.status_code == 200, r.body.text()
        rj = r.body.json()
        LOG.warning(rj)
        assert rj["proposalState"] == "Accepted", r.body.json()
        assert len(rj["voteFailures"]) == 1, rj["voteFailures"]
        member_id = network.consortium.get_member_by_local_id("member0").service_id
        assert rj["voteFailures"][member_id]["reason"] == f"Error: {error_body}", rj[
            "voteFailures"
        ]

    return network


@reqs.description("Test operator proposals and votes")
def test_operator_proposals_and_votes(network, args):
    node = choose_node(network)
    with node.api_versioned_client(
        None, None, "member0", api_version=args.gov_api_version
    ) as c:
        r = c.post("/gov/members/proposals:create", always_accept_if_voted_by_operator)
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["proposalState"] == "Open", r.body.json()
        proposal_id = r.body.json()["proposalId"]

        ballot = ballot_yes
        member_id = network.consortium.get_member_by_local_id("member0").service_id
        r = c.post(
            f"/gov/members/proposals/{proposal_id}/ballots/{member_id}:submit", ballot
        )
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["proposalState"] == "Accepted", r.body.json()

        r = c.post(
            "/gov/members/proposals:create", always_accept_if_proposed_by_operator
        )
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["proposalState"] == "Accepted", r.body.json()

    return network


@reqs.description("Test operator provisioner proposals")
def test_operator_provisioner_proposals_and_votes(network, args):
    node = choose_node(network)

    def propose_and_assert_accepted(signer_id, proposal):
        with node.api_versioned_client(
            None, None, signer_id, api_version=args.gov_api_version
        ) as c:
            r = c.post("/gov/members/proposals:create", proposal)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["proposalState"] == "Accepted", r.body.json()

    # Create an operator provisioner
    operator_provisioner = network.consortium.generate_and_add_new_member(
        remote_node=node,
        curve=args.participants_curve,
        member_data={"is_operator_provisioner": True},
    )
    operator_provisioner.ack(node)

    # Propose the creation of an operator signed by the operator provisioner
    operator = infra.member.Member(
        "operator",
        network.consortium.common_dir,
        network.consortium.share_script,
        recovery_role=infra.member.RecoveryRole.NonParticipant,
        key_generator=network.consortium.key_generator,
        curve=args.participants_curve,
        authenticate_session=network.consortium.authenticate_session,
        gov_api_impl=network.consortium.gov_api_impl,
    )

    cert_file = os.path.join(node.common_dir, operator.member_info["certificate_file"])
    set_operator, _ = network.consortium.make_proposal(
        "set_member",
        cert=open(
            cert_file,
            encoding="utf-8",
        ).read(),
        member_data={"is_operator": True},
    )

    propose_and_assert_accepted(
        signer_id=operator_provisioner.local_id,
        proposal=set_operator,
    )
    network.consortium.add_member(operator)
    operator.ack(node)

    # Propose the removal of the operator signed by the operator provisioner
    remove_operator, _ = network.consortium.make_proposal(
        "remove_member",
        member_id=operator.service_id,
    )

    propose_and_assert_accepted(
        signer_id=operator_provisioner.local_id,
        proposal=remove_operator,
    )
    network.consortium.members.remove(operator)
    operator.set_retired()

    # Create a proposal that the operator provisioner isn't allowed to approve.
    illegal_proposal, _ = network.consortium.make_proposal(
        "set_member_data",
        member_id=network.consortium.get_member_by_local_id("member0").service_id,
        member_data={},
    )
    with node.api_versioned_client(
        None, None, "member0", api_version=args.gov_api_version
    ) as c:
        r = c.post("/gov/members/proposals:create", illegal_proposal)
        assert r.status_code == 200, r.body.text()
        # Unlike earlier proposals, this is _not_ immediately approved
        assert r.body.json()["proposalState"] == "Open", r.body.json()

    network.consortium.members.remove(operator_provisioner)
    operator_provisioner.set_retired()


@reqs.description("Test actions")
def test_actions(network, args):
    node = choose_node(network)

    # Rekey ledger
    network.consortium.trigger_ledger_rekey(node)

    # Add new user twice (with and without user data)
    new_user_local_id = "js_user"
    new_user = network.create_user(new_user_local_id, args.participants_curve)
    LOG.info(f"Adding new user {new_user.service_id}")

    user_data = None
    network.consortium.add_user(node, new_user.local_id, user_data)

    user_data = {"foo": "bar"}
    network.consortium.add_user(node, new_user.local_id, user_data)

    with node.client(new_user.local_id) as c:
        r = c.post("/app/log/private", {"id": 0, "msg": "JS"})
        assert r.status_code == 200, r.body.text()

    # Set user data
    network.consortium.set_user_data(
        node, new_user.service_id, user_data={"user": "data"}
    )
    network.consortium.set_user_data(node, new_user.service_id, user_data=None)

    # Remove user
    network.consortium.remove_user(node, new_user.service_id)

    with node.client(new_user.local_id) as c:
        r = c.get("/app/log/private")
        assert r.status_code == 401, r.body.text()

    # Set member data
    network.consortium.set_member_data(
        node,
        network.consortium.get_member_by_local_id("member0").service_id,
        member_data={"is_operator": True, "is_admin": True},
    )

    # Set recovery threshold
    try:
        network.consortium.set_recovery_threshold(node, recovery_threshold=0)
        assert False, "Recovery threshold cannot be set to zero"
    except infra.proposal.ProposalNotCreated as e:
        assert (
            e.response.status_code == 400
            and e.response.body.json()["error"]["code"] == "ProposalFailedToValidate"
        ), e.response.body.text()

    try:
        network.consortium.set_recovery_threshold(node, recovery_threshold=256)
        assert False, "Recovery threshold cannot be set to > 255"
    except infra.proposal.ProposalNotCreated as e:
        assert (
            e.response.status_code == 400
            and e.response.body.json()["error"]["code"] == "ProposalFailedToValidate"
        ), e.response.body.text()

    try:
        network.consortium.set_recovery_threshold(node, recovery_threshold=None)
        assert False, "Recovery threshold value must be passed as proposal argument"
    except infra.proposal.ProposalNotCreated as e:
        assert (
            e.response.status_code == 400
            and e.response.body.json()["error"]["code"] == "ProposalFailedToValidate"
        ), e.response.body.text()

    try:
        network.consortium.set_recovery_threshold(
            node,
            recovery_threshold=len(
                network.consortium.get_active_recovery_participants()
            )
            + 1,
        )
        assert (
            False
        ), "Recovery threshold cannot be greater than the number of active recovery members"
    except infra.proposal.ProposalNotAccepted:
        pass

    network.consortium.set_recovery_threshold(
        node, recovery_threshold=network.consortium.recovery_threshold - 1
    )

    # Refresh recovery shares
    network.consortium.trigger_recovery_shares_refresh(node)

    # Set member
    new_member = network.consortium.generate_and_add_new_member(
        node, args.participants_curve
    )

    member_data = {"foo": "bar"}
    new_member = network.consortium.generate_and_add_new_member(
        node, args.participants_curve, member_data=member_data
    )

    # Remove member
    network.consortium.remove_member(node, new_member)
    network.consortium.remove_member(node, new_member)

    return network


@reqs.description("Test resolve and apply failures")
def test_apply(network, args):
    node = choose_node(network)

    with node.api_versioned_client(
        None, None, "member0", api_version=args.gov_api_version
    ) as c:
        member_id = network.consortium.get_member_by_local_id("member0").service_id

        r = c.post(
            "/gov/members/proposals:create", proposal(action("always_throw_in_apply"))
        )
        assert r.status_code == 500, r.body.text()
        assert r.body.json()["error"]["code"] == "InternalError", r.body.json()
        assert (
            r.body.json()["error"]["message"].split("\n")[0]
            == "Failed to apply(): Error: Error message"
        ), r.body.json()

        r = c.post(
            "/gov/members/proposals:create",
            proposal(action("always_accept_noop"), action("always_throw_in_apply")),
        )
        assert r.status_code == 200, r.body().text()
        proposal_id = r.body.json()["proposalId"]
        r = c.post(
            f"/gov/members/proposals/{proposal_id}/ballots/{member_id}:submit",
            ballot_yes,
        )
        assert r.status_code == 200, r.body().text()

        with node.api_versioned_client(
            None, None, "member1", api_version=args.gov_api_version
        ) as oc:
            member_id = network.consortium.get_member_by_local_id("member1").service_id

            r = oc.post(
                f"/gov/members/proposals/{proposal_id}/ballots/{member_id}:submit",
                ballot_yes,
            )
            assert r.body.json()["error"]["code"] == "InternalError", r.body.json()
            assert (
                "Failed to apply():" in r.body.json()["error"]["message"]
            ), r.body.json()
            assert (
                "Error: Error message" in r.body.json()["error"]["message"]
            ), r.body.json()

        r = c.post(
            "/gov/members/proposals:create",
            proposal(action("always_throw_in_resolve")),
        )
        assert r.status_code == 500, r.body.text()
        assert r.body.json()["error"]["code"] == "InternalError", r.body.json()
        assert (
            "Failed to resolve():" in r.body.json()["error"]["message"]
        ), r.body.json()
        assert (
            "Error: Resolve message" in r.body.json()["error"]["message"]
        ), r.body.json()

    return network


@reqs.description("Test set_constitution")
def test_set_constitution(network, args):
    node = choose_node(network)

    infra.clients.get_clock().advance()
    # Create some open proposals
    pending_proposals = []
    with node.api_versioned_client(
        None, None, "member0", api_version=args.gov_api_version
    ) as c:
        r = c.post(
            "/gov/members/proposals:create",
            valid_set_recovery_threshold,
        )
        assert r.status_code == 200, r.body.text()
        body = r.body.json()
        assert body["proposalState"] == "Open", body
        pending_proposals.append(body["proposalId"])

        r = c.post(
            "/gov/members/proposals:create",
            always_accept_with_one_vote,
        )
        assert r.status_code == 200, r.body.text()
        body = r.body.json()
        assert body["proposalState"] == "Open", body
        pending_proposals.append(body["proposalId"])

        r = c.get("/gov/service/constitution")
        assert r.status_code == 200, r
        constitution_before = r.body.text()

    # Create a set_constitution proposal, with test proposals removed, and pass it
    original_constitution = args.constitution
    modified_constitution = [
        path for path in original_constitution if "test_actions.js" not in path
    ]
    network.consortium.set_constitution(node, modified_constitution)

    with node.api_versioned_client(
        None, None, "member0", api_version=args.gov_api_version
    ) as c:
        # Check all other proposals were dropped
        for proposal_id in pending_proposals:
            r = c.get(f"/gov/members/proposals/{proposal_id}")
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["proposalState"] == "Dropped", r.body.json()

        # Confirm constitution has changed by proposing test actions which are no longer present
        r = c.post(
            "/gov/members/proposals:create",
            always_accept_noop,
        )
        assert (
            r.status_code == 400
            and r.body.json()["error"]["code"] == "ProposalFailedToValidate"
        ), r.body.text()

        # Confirm constitution has changed by comparing against previous kv value
        r = c.get("/gov/service/constitution")
        assert r.status_code == 200, r
        constitution_after = r.body.text()
        assert constitution_before != constitution_after

        r = c.post(
            "/gov/members/proposals:create",
            always_reject_noop,
        )
        assert (
            r.status_code == 400
            and r.body.json()["error"]["code"] == "ProposalFailedToValidate"
        ), r.body.text()

        infra.clients.get_clock().advance()
        # Confirm modified constitution can still accept valid proposals
        r = c.post(
            "/gov/members/proposals:create",
            valid_set_recovery_threshold,
        )
        assert r.status_code == 200, r.body.text()
        body = r.body.json()
        assert body["proposalState"] == "Open", body

        # Restore original constitution
        network.consortium.set_constitution(node, original_constitution)

        # Confirm original constitution was restored
        r = c.post(
            "/gov/members/proposals:create",
            always_accept_noop,
        )
        assert r.status_code == 200, r.body.text()
        body = r.body.json()
        assert body["proposalState"] == "Accepted", body

    return network


@reqs.description("Test validation in set_constitution")
def test_set_constitution_validation(network, args):
    node = choose_node(network)

    # NB: This tests the behaviour of the current default sample constitution,
    # and the validation it applies. In particular, it explicitly checks that
    # the proposed constitution is a string, before calling the CCF-provided
    # validateConstitution API (resulting in the specific errors below).
    # Other constitutions may choose to do more or less validation.
    for constitution, error_snippet in (
        ("", "is empty"),
        (1, "must be of type string"),
        (["a", "b", "c"], "must be of type string"),
        (None, "must be of type string"),
        ("Not syntactically valid JS", "Failed to compile"),
        (
            """
            export function resolve(proposal, proposerId, votes) {}
            export function apply(proposal, proposerId) {}
            """,
            "Failed to find export 'validate'",
        ),
        (
            """
            export function validate(input) {}
            export function apply(proposal, proposerId) {}
            """,
            "Failed to find export 'resolve'",
        ),
        (
            """
            export function validate(input) {}
            export function resolve(proposal, proposerId, votes) {}
            """,
            "Failed to find export 'apply'",
        ),
        (
            """
            export function validate(input) {}
            export function resolve(notEnoughArgs) {}
            export function apply(proposal, proposerId) {}
            """,
            "exports function resolve with 1 arg, expected between 3 and 4 args",
        ),
        (
            """
            export function validate(too, many, args) {}
            export function resolve(proposal, proposerId, votes) {}
            export function apply(proposal, proposerId) {}
            """,
            "exports function validate with 3 args, expected 1 arg",
        ),
    ):
        try:
            network.consortium.set_constitution_raw(node, constitution)
        except infra.proposal.ProposalNotCreated as e:
            r = e.response
            assert r.status_code == 400, r
            message = r.body.json()["error"]["message"]
            assert (
                error_snippet in message
            ), f"Expected content ({error_snippet}) not found in response:\n{r.body.text()}"
        else:
            assert (
                False
            ), f"Expected error from validateConstitution for: '{constitution}'"

    # Minimal valid constitutions
    apply_body = """
        const proposed_actions = JSON.parse(proposal)["actions"];
        if (proposed_actions.length !== 1 || proposed_actions[0].name !== "set_constitution")
        {
            throw new Error("This minimal constitution only allows other set_constitution proposals");
        }
        ccf.kv["public:ccf.gov.constitution"].set(
            new ArrayBuffer(8),
            ccf.jsonCompatibleToBuf(proposed_actions[0].args.constitution));
        """
    for constitution in (
        """
        export function validate(input) { return {valid: true} }
        export function resolve(proposal, proposerId, votes) { return "Accepted" }
        export function apply(proposal, proposerId) { """
        + apply_body
        + "}",
        """
        export function validate(input) { return {valid: true} }
        export function resolve(proposal, proposerId, votes, proposalId) { return "Accepted" }
        export function apply(proposal, proposerId) { """
        + apply_body
        + "}",
    ):
        network.consortium.set_constitution_raw(node, constitution)

    # Reset original constitution
    network.consortium.set_constitution(node, args.constitution)

    return network


@contextmanager
def temporary_constitution(network, args, js_constitution_suffix):
    primary, _ = network.find_primary()
    original_constitution = args.constitution
    with tempfile.NamedTemporaryFile("w") as f:
        f.write(js_constitution_suffix)
        f.flush()

        modified_constitution = [path for path in original_constitution] + [f.name]
        network.consortium.set_constitution(primary, modified_constitution)

        yield

    network.consortium.set_constitution(primary, original_constitution)


def make_action_snippet(action_name, validate="", apply=""):
    return f"""
actions.set(
    "{action_name}",
    new Action(
        function validate(args) {{ {validate} }},
        function apply(args, proposalId) {{ {apply} }}
    )
)
"""


@reqs.description("Test read-write restrictions")
def test_read_write_restrictions(network, args):
    primary, _ = network.find_primary()

    consortium = network.consortium

    LOG.info("Test basic constitution replacement")
    with temporary_constitution(
        network,
        args,
        make_action_snippet(
            "hello_world",
            validate="console.log('Validating a hello_world action')",
            apply="console.log('Applying a hello_world action')",
        ),
    ):
        proposal_body, vote = consortium.make_proposal("hello_world")
        proposal = consortium.get_any_active_member().propose(primary, proposal_body)
        consortium.vote_using_majority(primary, proposal, vote)

    @dataclasses.dataclass
    class TestSpec:
        description: str
        table_name: str

        readable_in_validate: bool = True
        writable_in_validate: bool = True

        readable_in_apply: bool = True
        writable_in_apply: bool = True

        error_contents: list = dataclasses.field(default_factory=list)

    tests = [
        # Governance tables
        TestSpec(
            description="Public governance tables cannot be modified during validation",
            table_name="public:ccf.gov.my_custom_table",
            writable_in_validate=False,
        ),
        TestSpec(
            description="Private governance tables cannot even be read",
            table_name="ccf.gov.my_custom_table",
            readable_in_validate=False,
            writable_in_validate=False,
            readable_in_apply=False,
            writable_in_apply=False,
        ),
        # Internal tables
        TestSpec(
            description="Public internal tables are read-only",
            table_name="public:ccf.internal.my_custom_table",
            writable_in_validate=False,
            writable_in_apply=False,
        ),
        TestSpec(
            description="Private internal tables cannot even be read",
            table_name="ccf.internal.my_custom_table",
            readable_in_validate=False,
            writable_in_validate=False,
            readable_in_apply=False,
            writable_in_apply=False,
        ),
        # Application tables
        TestSpec(
            description="Public application tables cannot even be read, apart from during apply where they can be written",
            table_name="public:my.app.my_custom_table",
            readable_in_validate=False,
            writable_in_validate=False,
            readable_in_apply=False,
            writable_in_apply=True,
        ),
        TestSpec(
            description="Private application tables cannot even be read",
            table_name="my.app.my_custom_table",
            readable_in_validate=False,
            writable_in_validate=False,
            readable_in_apply=False,
            writable_in_apply=False,
        ),
    ]

    def make_script(table_name, kind):
        return f"""
const table_name = "{table_name}";
var table = ccf.kv[table_name];
if (args.try.includes("read_during_{kind}")) {{ table.get(getSingletonKvKey()); }}
if (args.try.includes("write_during_{kind}")) {{ table.delete(getSingletonKvKey()); }}
"""

    action_name = "temp_action"

    for test in tests:
        LOG.info(test.description)
        with temporary_constitution(
            network,
            args,
            make_action_snippet(
                action_name,
                validate=make_script(test.table_name, "validate"),
                apply=make_script(test.table_name, "apply"),
            ),
        ):
            for should_succeed, proposal_args in (
                (test.readable_in_validate, {"try": ["read_during_validate"]}),
                (test.writable_in_validate, {"try": ["write_during_validate"]}),
                (test.readable_in_apply, {"try": ["read_during_apply"]}),
                (test.writable_in_apply, {"try": ["write_during_apply"]}),
            ):
                proposal_body, vote = consortium.make_proposal(
                    action_name, **proposal_args
                )
                desc = f"during '{test.description}', doing {proposal_args}, expecting {should_succeed}"
                try:
                    proposal = consortium.get_any_active_member().propose(
                        primary, proposal_body
                    )
                    consortium.vote_using_majority(primary, proposal, vote)
                    assert should_succeed, f"Proposal was applied unexpectedly ({desc})"
                except (
                    infra.proposal.ProposalNotCreated,
                    infra.proposal.ProposalNotAccepted,
                ) as e:
                    msg = e.response.body.json()["error"]["message"]
                    assert (
                        not should_succeed
                    ), f"Proposal failed unexpectedly ({desc}): {msg}"

    return network


@reqs.description("Test access to accepted proposal state")
def test_final_proposal_visibility(network, args):
    primary, _ = network.find_primary()
    consortium = network.consortium

    with temporary_constitution(
        network,
        args,
        # An proposal that counts who voted for it.
        # Proving that such a thing is _possible_, but in practice we mostly expect that this visibility will only be used for reporting.
        make_action_snippet(
            "vote_provenance",
            apply="""
            let proposals = ccf.kv["public:ccf.gov.proposals_info"];
            let proposalInfoBuffer = proposals.get(ccf.strToBuf(proposalId));
            if (proposalInfoBuffer === undefined) { throw new Error(`Can't find proposal info for ${proposalId}`); }
            const proposalInfo = ccf.bufToJsonCompatible(proposalInfoBuffer);
            const state = proposalInfo.state;
            if (state != "Accepted") { throw new Error(`apply() received proposal in unexpected state ${state}`); }
            const finalVotes = proposalInfo.final_votes;
            if (finalVotes === undefined) { throw new Error("Don't have finalVotes"); }

            let supporters = ccf.kv["public:ccf.gov.testonly.supporter_points"];
            for (const [memberId, vote] of Object.entries(finalVotes)) {
                const memberIdBuf = ccf.strToBuf(memberId);
                if (vote === true) {
                    if (supporters.has(memberIdBuf)) {
                        const prev = ccf.bufToJsonCompatible(supporters.get(memberIdBuf));
                        supporters.set(memberIdBuf, ccf.jsonCompatibleToBuf(prev + 1));
                    } else {
                        supporters.set(memberIdBuf, ccf.jsonCompatibleToBuf(1));
                    }
                } else {
                    // Null points for anyone who voted against this
                    supporters.set(memberIdBuf, ccf.jsonCompatibleToBuf(0));
                }
            }

            console.log("Current supporter scoreboard is:");
            supporters.forEach((v, k) => {
                console.log(`  Member ${ccf.bufToStr(k)} has ${ccf.bufToJsonCompatible(v)} points`);
            });
""",
        ),
    ):
        members = consortium.get_active_members()
        assert len(members) >= 3
        booster = members[0]
        fairweather = members[1]
        turncoat = members[2]

        proposal_body, ballot = consortium.make_proposal("vote_provenance")

        first = consortium.get_any_active_member().propose(primary, proposal_body)
        response = booster.vote(primary, first, ballot)
        assert response.status_code == 200
        response = turncoat.vote(primary, first, ballot)
        assert response.status_code == 200

        second = consortium.get_any_active_member().propose(primary, proposal_body)
        response = booster.vote(primary, second, ballot)
        assert response.status_code == 200
        response = fairweather.vote(primary, second, ballot)
        assert response.status_code == 200

        third = consortium.get_any_active_member().propose(primary, proposal_body)
        response = booster.vote(primary, third, ballot)
        assert response.status_code == 200
        # Votes against! Loses supporter points!
        response = turncoat.vote(
            primary,
            third,
            json.dumps(
                {
                    "ballot": "export function vote (rawProposal, proposerId) { return false }"
                }
            ),
        )
        assert response.status_code == 200
        response = fairweather.vote(primary, third, ballot)
        assert response.status_code == 200

        LOG.info("Confirm that finalVotes is present in submit-ballot response")
        body = response.body.json()
        assert "finalVotes" in body, body

        LOG.info("Confirm that finalVotes is present in get-proposal response")
        body = consortium.get_proposal_raw(primary, third.proposal_id)
        assert "finalVotes" in body, body

    LOG.info("Confirm that expected values were actually written to the KV")
    # To avoid creating an extra endpoint in the app, we smuggle a read into a new
    # action's apply, reported to the caller via an exception
    with temporary_constitution(
        network,
        args,
        make_action_snippet(
            "read_supporters",
            apply="""
            let supporters = ccf.kv["public:ccf.gov.testonly.supporter_points"];
            let s = "Current supporter scoreboard is:\\n";
            supporters.forEach((v, k) => {
                s += `  Member ${ccf.bufToStr(k)} has ${ccf.bufToJsonCompatible(v)} points\\n`;
            });
            throw new Error(s);
            """,
        ),
    ):

        proposal_body, ballot = consortium.make_proposal("read_supporters")

        proposal = consortium.get_any_active_member().propose(primary, proposal_body)

        expected_lines = [
            f"Member {booster.service_id} has 3 points",
            f"Member {fairweather.service_id} has 2 points",
            f"Member {turncoat.service_id} has 0 points",
        ]

        thrown = False
        try:
            consortium.vote_using_majority(primary, proposal, ballot)
        except infra.proposal.ProposalNotAccepted as e:
            thrown = True
            msg = e.response.body.json()["error"]["message"]
            for line in expected_lines:
                assert line in msg
        assert thrown

    return network


@reqs.description("Test final proposal description written to KV")
def test_ledger_governance_invariants(network, args):
    node = network.nodes[0]
    ledger_dirs = node.remote.ledger_paths()

    ledger = ccf.ledger.Ledger(ledger_dirs)

    LOG.info("Completed proposals contain final_vote for each submitted ballot")
    table_name = "public:ccf.gov.proposals_info"
    seen_states = set()
    for transaction in ledger.transactions():
        public_tables = transaction.get_public_domain().get_tables()
        if table_name not in public_tables:
            continue

        for _, raw_proposal in public_tables[table_name].items():
            if raw_proposal is None:
                # This is a deletion
                continue

            proposal = json.loads(raw_proposal)

            state = proposal["state"]
            seen_states.add(state)
            if state in ("Open", "Withdrawn", "Dropped"):
                # This proposal contains no final_votes
                continue

            ballots = proposal["ballots"]
            final_votes = proposal["final_votes"]
            vote_failures = proposal["vote_failures"]

            all_submitted = set(ballots.keys())
            all_results = set.union(set(final_votes.keys()), set(vote_failures.keys()))

            assert all_submitted == all_results, proposal

    LOG.info("Confirm that previous tests properly stressed this behaviour")
    expected = {
        "Accepted",
        "Dropped",
        # "Failed", # This state produces an error, and is never written to the KV
        "Open",
        "Rejected",
        "Withdrawn",
    }
    diff = seen_states.symmetric_difference(expected)
    assert len(diff) == 0, diff

    return network
