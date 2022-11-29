# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs
import os
from loguru import logger as LOG
import pprint


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

ballot_yes = vote("return true")
ballot_no = vote("return false")


@reqs.description("Test proposal validation")
def test_proposal_validation(network, args):
    node = network.find_random_node()

    def assert_invalid_proposal(r):
        assert (
            r.status_code == 400
            and r.body.json()["error"]["code"] == "ProposalFailedToValidate"
        ), r.body.text()

    def assert_malformed_proposal(r):
        assert (
            r.status_code == 500
            and r.body.json()["error"]["code"] == "InternalError"
            and r.body.json()["error"]["message"].startswith(
                "Failed to execute validation: SyntaxError:"
            )
        ), r.body.text()

    with node.client(None, "member0") as c:

        r = c.post(
            "/gov/proposals",
            b"{ not valid json",
        )
        assert_malformed_proposal(r)

        r = c.post(
            "/gov/proposals",
            proposal(action("valid_pem", pem="That's not a PEM")),
        )
        assert_invalid_proposal(r)

        with open(
            os.path.join(network.common_dir, "service_cert.pem"), "r", encoding="utf-8"
        ) as cert:
            valid_pem = cert.read()

        r = c.post(
            "/gov/proposals",
            proposal(action("valid_pem", pem=valid_pem)),
        )
        assert r.status_code == 200

        # Arg missing
        r = c.post(
            "/gov/proposals",
            proposal(action("remove_user")),
        )
        assert_invalid_proposal(r)

        # Not a string
        r = c.post(
            "/gov/proposals",
            proposal(action("remove_user", user_id=42)),
        )
        assert_invalid_proposal(r)

        # Too short
        r = c.post(
            "/gov/proposals",
            proposal(action("remove_user", user_id="deadbeef")),
        )
        assert_invalid_proposal(r)

        # Too long
        r = c.post(
            "/gov/proposals",
            proposal(
                action(
                    "remove_user",
                    user_id="0deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                )
            ),
        )
        assert_invalid_proposal(r)

        # Not hex
        r = c.post(
            "/gov/proposals",
            proposal(
                action(
                    "remove_user",
                    user_id="totboeuftotboeuftotboeuftotboeuftotboeuftotboeuftotboeuftotboeuf",
                )
            ),
        )
        assert_invalid_proposal(r)

        # Just right
        # NB: It validates (structurally correct type), but does nothing because this user doesn't exist
        r = c.post(
            "/gov/proposals",
            proposal(
                action(
                    "remove_user",
                    user_id="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                )
            ),
        )
        assert r.status_code == 200

    return network


@reqs.description("Test proposal storage")
def test_proposal_storage(network, args):
    node = network.find_random_node()

    with node.client(None, "member0") as c:
        r = c.get("/gov/proposals/42")
        assert r.status_code == 404, r.body.text()

        r = c.get("/gov/proposals/42/actions")
        assert r.status_code == 404, r.body.text()

        for prop in (valid_set_recovery_threshold, valid_set_recovery_threshold_twice):
            r = c.post("/gov/proposals", prop)
            assert r.status_code == 200, r.body.text()
            proposal_id = r.body.json()["proposal_id"]

            r = c.get(f"/gov/proposals/{proposal_id}")
            assert r.status_code == 200, r.body.text()
            expected = {
                "proposer_id": network.consortium.get_member_by_local_id(
                    "member0"
                ).service_id,
                "state": "Open",
                "ballots": {},
            }
            assert r.body.json() == expected, r.body.json()

            r = c.get(f"/gov/proposals/{proposal_id}/actions")
            assert r.status_code == 200, r.body.text()
            assert r.body.json() == prop, r.body.json()

    return network


@reqs.description("Test proposal withdrawal")
def test_proposal_withdrawal(network, args):
    node = network.find_random_node()

    with node.client(None, "member0") as c:
        for prop in (valid_set_recovery_threshold, valid_set_recovery_threshold_twice):
            r = c.post("/gov/proposals/42/withdraw")
            assert r.status_code == 400, r.body.text()

            r = c.post("/gov/proposals", prop)
            assert r.status_code == 200, r.body.text()
            proposal_id = r.body.json()["proposal_id"]

            with node.client(None, "member1") as oc:
                r = oc.post(f"/gov/proposals/{proposal_id}/withdraw")
                assert r.status_code == 403, r.body.text()

            r = c.get(f"/gov/proposals/{proposal_id}")
            assert r.status_code == 200, r.body.text()
            expected = {
                "proposer_id": network.consortium.get_member_by_local_id(
                    "member0"
                ).service_id,
                "state": "Open",
                "ballots": {},
            }
            assert r.body.json() == expected, r.body.json()

            r = c.post(f"/gov/proposals/{proposal_id}/withdraw")
            assert r.status_code == 200, r.body.text()
            expected = {
                "proposer_id": network.consortium.get_member_by_local_id(
                    "member0"
                ).service_id,
                "state": "Withdrawn",
                "ballots": {},
            }
            assert r.body.json() == expected, r.body.json()

            r = c.post(f"/gov/proposals/{proposal_id}/withdraw")
            assert r.status_code == 400, r.body.text()

    return network


@reqs.description("Test ballot storage and validation")
def test_ballot_storage(network, args):
    node = network.find_random_node()

    with node.client(None, "member0") as c:
        r = c.post("/gov/proposals", valid_set_recovery_threshold)
        assert r.status_code == 200, r.body.text()
        proposal_id = r.body.json()["proposal_id"]

        r = c.post(f"/gov/proposals/{proposal_id}/ballots", {})
        assert r.status_code == 400, r.body.text()

        ballot = ballot_yes
        r = c.post(f"/gov/proposals/{proposal_id}/ballots", ballot)
        assert r.status_code == 200, r.body.text()

        r = c.post(f"/gov/proposals/{proposal_id}/ballots", ballot)
        assert r.status_code == 400, r.body.text()
        assert r.body.json()["error"]["code"] == "VoteAlreadyExists", r.body.json()

        member_id = network.consortium.get_member_by_local_id("member0").service_id
        r = c.get(f"/gov/proposals/{proposal_id}/ballots/{member_id}")
        assert r.status_code == 200, r.body.text()
        assert r.body.json() == ballot, r.body.json()

    with node.client(None, "member1") as c:
        ballot = ballot_no
        r = c.post(f"/gov/proposals/{proposal_id}/ballots", ballot)
        assert r.status_code == 200, r.body.text()
        member_id = network.consortium.get_member_by_local_id("member1").service_id
        r = c.get(f"/gov/proposals/{proposal_id}/ballots/{member_id}")
        assert r.status_code == 200, r.body.text()
        assert r.body.json() == ballot

    return network


@reqs.description("Test pure proposals")
def test_pure_proposals(network, args):
    node = network.find_random_node()

    with node.client(None, "member0") as c:
        for prop, state in [
            (always_accept_noop, "Accepted"),
            (always_reject_noop, "Rejected"),
        ]:
            r = c.post("/gov/proposals", prop)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == state, r.body.json()
            proposal_id = r.body.json()["proposal_id"]

            ballot = ballot_yes
            r = c.post(f"/gov/proposals/{proposal_id}/ballots", ballot)
            assert r.status_code == 400, r.body.text()

            r = c.post(f"/gov/proposals/{proposal_id}/withdraw")
            assert r.status_code == 400, r.body.text()

    return network


@reqs.description("Test open proposals")
def test_all_open_proposals(network, args):
    node = network.find_random_node()
    with node.client(None, "member0") as c:
        r = c.post("/gov/proposals", always_accept_noop)
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] == "Accepted", r.body.json()

        r = c.get("/gov/proposals")
        assert r.body.json() == {}

        r = c.post("/gov/proposals", always_accept_with_one_vote)
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] == "Open", r.body.json()

        r = c.get("/gov/proposals")
        resp = r.body.json()
        for _, value in resp.items():
            assert value["state"] == "Open"

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
    node = network.find_random_node()
    with node.client(None, "member0") as c:
        for prop, state, direction in [
            (always_accept_with_one_vote, "Accepted", "true"),
            (always_reject_with_one_vote, "Rejected", "false"),
        ]:
            r = c.post("/gov/proposals", prop)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == "Open", r.body.json()
            proposal_id = r.body.json()["proposal_id"]

            ballot = vote(f"return {direction}")
            r = c.post(f"/gov/proposals/{proposal_id}/ballots", ballot)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == state, r.body.json()

            r = c.post("/gov/proposals", prop)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == "Open", r.body.json()
            proposal_id = r.body.json()["proposal_id"]

            member_id = network.consortium.get_member_by_local_id("member0").service_id
            ballot = vote(
                f'if (proposer_id == "{member_id}") {{ return {direction} }} else {{ return {opposite(direction) } }}'
            )
            r = c.post(f"/gov/proposals/{proposal_id}/ballots", ballot)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == state, r.body.json()

    with node.client(None, "member0") as c:
        for prop, state, ballot in [
            (always_accept_with_two_votes, "Accepted", ballot_yes),
            (always_reject_with_two_votes, "Rejected", ballot_no),
        ]:
            r = c.post("/gov/proposals", prop)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == "Open", r.body.json()
            proposal_id = r.body.json()["proposal_id"]

            r = c.post(f"/gov/proposals/{proposal_id}/ballots", ballot)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == "Open", r.body.json()

            with node.client(None, "member1") as oc:
                r = oc.post(f"/gov/proposals/{proposal_id}/ballots", ballot)
                assert r.status_code == 200, r.body.text()
                assert r.body.json()["state"] == state, r.body.json()

    return network


@reqs.description("Test vote failure reporting")
def test_vote_failure_reporting(network, args):
    node = network.find_random_node()
    with node.client(None, "member0") as c:
        r = c.post("/gov/proposals", always_accept_with_one_vote)
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] == "Open", r.body.json()
        proposal_id = r.body.json()["proposal_id"]

        ballot = vote('throw new Error("Sample error")')
        r = c.post(f"/gov/proposals/{proposal_id}/ballots", ballot)
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] == "Open", r.body.json()

    with node.client(None, "member1") as c:
        ballot = ballot_yes
        r = c.post(f"/gov/proposals/{proposal_id}/ballots", ballot)
        assert r.status_code == 200, r.body.text()
        rj = r.body.json()
        assert rj["state"] == "Accepted", r.body.json()
        assert len(rj["vote_failures"]) == 1, rj["vote_failures"]
        member_id = network.consortium.get_member_by_local_id("member0").service_id
        assert rj["vote_failures"][member_id]["reason"] == "Error: Sample error", rj[
            "vote_failures"
        ]

    return network


@reqs.description("Test operator proposals and votes")
def test_operator_proposals_and_votes(network, args):
    node = network.find_random_node()
    with node.client(None, "member0") as c:
        r = c.post("/gov/proposals", always_accept_if_voted_by_operator)
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] == "Open", r.body.json()
        proposal_id = r.body.json()["proposal_id"]

        ballot = ballot_yes
        r = c.post(f"/gov/proposals/{proposal_id}/ballots", ballot)
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] == "Accepted", r.body.json()

    with node.client(None, "member0") as c:
        r = c.post("/gov/proposals", always_accept_if_proposed_by_operator)
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] == "Accepted", r.body.json()
        proposal_id = r.body.json()["proposal_id"]

    return network


@reqs.description("Test operator provisioner proposals")
def test_operator_provisioner_proposals_and_votes(network, args):

    node = network.find_random_node()

    def propose_and_assert_accepted(signer_id, proposal):
        with node.client(None, signer_id) as c:
            r = c.post("/gov/proposals", proposal)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == "Accepted", r.body.json()

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
        args.participants_curve,
        network.consortium.common_dir,
        network.consortium.share_script,
        is_recovery_member=False,
        key_generator=network.consortium.key_generator,
        authenticate_session=network.consortium.authenticate_session,
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
    network.consortium.members.append(operator)
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

    # Create a proposal that the operator provisioner isn't allowed to make.
    illegal_proposal, _ = network.consortium.make_proposal(
        "set_member_data",
        member_id=network.consortium.get_member_by_local_id("member0").service_id,
        member_data={},
    )
    with node.client(None, "member0") as c:
        r = c.post("/gov/proposals", illegal_proposal)
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] != "Accepted", r.body.json()

    network.consortium.members.remove(operator_provisioner)
    operator_provisioner.set_retired()


@reqs.description("Test actions")
def test_actions(network, args):
    node = network.find_random_node()

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
            recovery_threshold=len(network.consortium.get_active_recovery_members())
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
    node = network.find_random_node()

    with node.client(None, "member0") as c:
        r = c.post(
            "/gov/proposals",
            proposal(action("always_throw_in_apply")),
        )
        assert r.status_code == 500, r.body.text()
        assert r.body.json()["error"]["code"] == "InternalError", r.body.json()
        assert (
            r.body.json()["error"]["message"].split("\n")[0]
            == "Failed to apply(): Error: Error message"
        ), r.body.json()

    with node.client(None, "member0") as c:
        pprint.pprint(
            proposal(action("always_accept_noop"), action("always_throw_in_apply"))
        )
        r = c.post(
            "/gov/proposals",
            proposal(action("always_accept_noop"), action("always_throw_in_apply")),
        )
        assert r.status_code == 200, r.body().text()
        proposal_id = r.body.json()["proposal_id"]
        r = c.post(f"/gov/proposals/{proposal_id}/ballots", ballot_yes)
        assert r.status_code == 200, r.body().text()

        with node.client(None, "member1") as c:
            r = c.post(f"/gov/proposals/{proposal_id}/ballots", ballot_yes)
            assert r.body.json()["error"]["code"] == "InternalError", r.body.json()
            assert (
                "Failed to apply():" in r.body.json()["error"]["message"]
            ), r.body.json()
            assert (
                "Error: Error message" in r.body.json()["error"]["message"]
            ), r.body.json()

    with node.client(None, "member0") as c:
        r = c.post(
            "/gov/proposals",
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
    node = network.find_random_node()

    # Create some open proposals
    pending_proposals = []
    with node.client(None, "member0") as c:
        r = c.post(
            "/gov/proposals",
            valid_set_recovery_threshold,
        )
        assert r.status_code == 200, r.body.text()
        body = r.body.json()
        assert body["state"] == "Open", body
        pending_proposals.append(body["proposal_id"])

        r = c.post(
            "/gov/proposals",
            always_accept_with_one_vote,
        )
        assert r.status_code == 200, r.body.text()
        body = r.body.json()
        assert body["state"] == "Open", body
        pending_proposals.append(body["proposal_id"])

        r = c.get(f"/gov/kv/constitution")
        assert r.status_code == 200, r
        constitution_before = r.body.json()

    # Create a set_constitution proposal, with test proposals removed, and pass it
    original_constitution = args.constitution
    modified_constitution = [
        path for path in original_constitution if "test_actions.js" not in path
    ]
    network.consortium.set_constitution(node, modified_constitution)

    with node.client(None, "member0") as c:
        # Check all other proposals were dropped
        for proposal_id in pending_proposals:
            r = c.get(f"/gov/proposals/{proposal_id}")
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == "Dropped", r.body.json()

        # Confirm constitution has changed by proposing test actions which are no longer present
        r = c.post(
            "/gov/proposals",
            always_accept_noop,
        )
        assert (
            r.status_code == 400
            and r.body.json()["error"]["code"] == "ProposalFailedToValidate"
        ), r.body.text()

        # Confirm constitution has changed by comparing against previous kv value
        r = c.get(f"/gov/kv/constitution")
        assert r.status_code == 200, r
        constitution_after = r.body.json()
        assert constitution_before != constitution_after

        r = c.post(
            "/gov/proposals",
            always_reject_noop,
        )
        assert (
            r.status_code == 400
            and r.body.json()["error"]["code"] == "ProposalFailedToValidate"
        ), r.body.text()

        # Confirm modified constitution can still accept valid proposals
        r = c.post(
            "/gov/proposals",
            valid_set_recovery_threshold,
        )
        assert r.status_code == 200, r.body.text()
        body = r.body.json()
        assert body["state"] == "Open", body

        # Restore original constitution
        network.consortium.set_constitution(node, original_constitution)

        # Confirm original constitution was restored
        r = c.post(
            "/gov/proposals",
            always_accept_noop,
        )
        assert r.status_code == 200, r.body.text()
        body = r.body.json()
        assert body["state"] == "Accepted", body

    return network
