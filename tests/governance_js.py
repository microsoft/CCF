# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs
import ccf.proposal_generator as prop_gen


def action(name, **args):
    return {"name": name, "args": args}


def proposal(*actions):
    return {"actions": list(actions)}


def merge(*proposals):
    return {"actions": sum((prop["actions"] for prop in proposals), [])}


valid_set_recovery_threshold = proposal(action("set_recovery_threshold", threshold=5))
valid_set_recovery_threshold_twice = merge(
    valid_set_recovery_threshold, valid_set_recovery_threshold
)
no_args_set_recovery_threshold = proposal(action("set_recovery_threshold"))
bad_arg_set_recovery_threshold = proposal(
    action("set_recovery_threshold", threshold=5000)
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


@reqs.description("Test proposal validation")
def test_proposal_validation(network, args):
    node = network.find_random_node()

    with node.client(None, "member0") as c:
        r = c.post("/gov/proposals.js", valid_set_recovery_threshold)
        assert r.status_code == 200, r.body.text()

        r = c.post("/gov/proposals.js", valid_set_recovery_threshold_twice)
        assert r.status_code == 200, r.body.text()

        r = c.post("/gov/proposals.js", no_args_set_recovery_threshold)
        assert (
            r.status_code == 400
            and r.body.json()["error"]["code"] == "ProposalFailedToValidate"
        ), r.body.text()

        r = c.post(
            "/gov/proposals.js",
            merge(no_args_set_recovery_threshold, bad_arg_set_recovery_threshold),
        )
        assert (
            r.status_code == 400
            and r.body.json()["error"]["code"] == "ProposalFailedToValidate"
        ), r.body.text()

    return network


@reqs.description("Test proposal storage")
def test_proposal_storage(network, args):
    node = network.find_random_node()

    with node.client(None, "member0") as c:
        r = c.get("/gov/proposals.js/42")
        assert r.status_code == 404, r.body.text()

        r = c.get("/gov/proposals.js/42/actions")
        assert r.status_code == 404, r.body.text()

        for prop in (valid_set_recovery_threshold, valid_set_recovery_threshold_twice):
            r = c.post("/gov/proposals.js", prop)
            assert r.status_code == 200, r.body.text()
            proposal_id = r.body.json()["proposal_id"]

            r = c.get(f"/gov/proposals.js/{proposal_id}")
            assert r.status_code == 200, r.body.text()
            expected = {
                "proposer_id": network.consortium.get_member_by_local_id(
                    "member0"
                ).service_id,
                "state": "Open",
                "ballots": [],
            }
            assert r.body.json() == expected, r.body.json()

            r = c.get(f"/gov/proposals.js/{proposal_id}/actions")
            assert r.status_code == 200, r.body.text()
            assert r.body.json() == prop, r.body.json()

    return network


@reqs.description("Test proposal withdrawal")
def test_proposal_withdrawal(network, args):
    node = network.find_random_node()

    with node.client(None, "member0") as c:
        for prop in (valid_set_recovery_threshold, valid_set_recovery_threshold_twice):
            r = c.post("/gov/proposals.js/42/withdraw")
            assert r.status_code == 400, r.body.text()

            r = c.post("/gov/proposals.js", prop)
            assert r.status_code == 200, r.body.text()
            proposal_id = r.body.json()["proposal_id"]

            with node.client(None, "member1") as oc:
                r = oc.post(f"/gov/proposals.js/{proposal_id}/withdraw")
                assert r.status_code == 403, r.body.text()

            r = c.get(f"/gov/proposals.js/{proposal_id}")
            assert r.status_code == 200, r.body.text()
            expected = {
                "proposer_id": network.consortium.get_member_by_local_id(
                    "member0"
                ).service_id,
                "state": "Open",
                "ballots": [],
            }
            assert r.body.json() == expected, r.body.json()

            r = c.post(f"/gov/proposals.js/{proposal_id}/withdraw")
            assert r.status_code == 200, r.body.text()
            expected = {
                "proposer_id": network.consortium.get_member_by_local_id(
                    "member0"
                ).service_id,
                "state": "Withdrawn",
                "ballots": [],
            }
            assert r.body.json() == expected, r.body.json()

            r = c.post(f"/gov/proposals.js/{proposal_id}/withdraw")
            assert r.status_code == 400, r.body.text()

    return network


@reqs.description("Test ballot storage and validation")
def test_ballot_storage(network, args):
    node = network.find_random_node()

    with node.client(None, "member0") as c:
        r = c.post("/gov/proposals.js", valid_set_recovery_threshold)
        assert r.status_code == 200, r.body.text()
        proposal_id = r.body.json()["proposal_id"]

        r = c.post(f"/gov/proposals.js/{proposal_id}/ballots", {})
        assert r.status_code == 400, r.body.text()

        ballot = {"ballot": "function vote (proposal, proposer_id) { return true }"}
        r = c.post(f"/gov/proposals.js/{proposal_id}/ballots", ballot)
        assert r.status_code == 200, r.body.text()

        member_id = network.consortium.get_member_by_local_id("member0").service_id
        r = c.get(f"/gov/proposals.js/{proposal_id}/ballots/{member_id}")
        assert r.status_code == 200, r.body.text()
        assert r.body.json() == ballot, r.body.json()

    with node.client(None, "member1") as c:
        ballot = {"ballot": "function vote (proposal, proposer_id) { return false }"}
        r = c.post(f"/gov/proposals.js/{proposal_id}/ballots", ballot)
        assert r.status_code == 200, r.body.text()
        member_id = network.consortium.get_member_by_local_id("member1").service_id
        r = c.get(f"/gov/proposals.js/{proposal_id}/ballots/{member_id}")
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
            r = c.post("/gov/proposals.js", prop)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == state, r.body.json()
            proposal_id = r.body.json()["proposal_id"]

            ballot = {"ballot": "function vote (proposal, proposer_id) { return true }"}
            r = c.post(f"/gov/proposals.js/{proposal_id}/ballots", ballot)
            assert r.status_code == 400, r.body.text()

            r = c.post(f"/gov/proposals.js/{proposal_id}/withdraw")
            assert r.status_code == 400, r.body.text()

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
            r = c.post("/gov/proposals.js", prop)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == "Open", r.body.json()
            proposal_id = r.body.json()["proposal_id"]

            ballot = {
                "ballot": f"function vote (proposal, proposer_id) {{ return {direction} }}"
            }
            r = c.post(f"/gov/proposals.js/{proposal_id}/ballots", ballot)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == state, r.body.json()

            r = c.post("/gov/proposals.js", prop)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == "Open", r.body.json()
            proposal_id = r.body.json()["proposal_id"]

            member_id = network.consortium.get_member_by_local_id("member0").service_id
            ballot = {
                "ballot": f'function vote (proposal, proposer_id) {{ if (proposer_id == "{member_id}") {{ return {direction} }} else {{ return {opposite(direction) } }} }}'
            }
            r = c.post(f"/gov/proposals.js/{proposal_id}/ballots", ballot)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == state, r.body.json()

    with node.client(None, "member0") as c:
        for prop, state, direction in [
            (always_accept_with_two_votes, "Accepted", "true"),
            (always_reject_with_two_votes, "Rejected", "false"),
        ]:
            r = c.post("/gov/proposals.js", prop)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == "Open", r.body.json()
            proposal_id = r.body.json()["proposal_id"]

            ballot = {
                "ballot": f"function vote (proposal, proposer_id) {{ return {direction} }}"
            }
            r = c.post(f"/gov/proposals.js/{proposal_id}/ballots", ballot)
            assert r.status_code == 200, r.body.text()
            assert r.body.json()["state"] == "Open", r.body.json()

            with node.client(None, "member1") as oc:
                ballot = {
                    "ballot": f"function vote (proposal, proposer_id) {{ return {direction} }}"
                }
                r = oc.post(f"/gov/proposals.js/{proposal_id}/ballots", ballot)
                assert r.status_code == 200, r.body.text()
                assert r.body.json()["state"] == state, r.body.json()

    return network


@reqs.description("Test operator proposals and votes")
def test_operator_proposals_and_votes(network, args):
    node = network.find_random_node()
    with node.client(None, "member0") as c:
        r = c.post("/gov/proposals.js", always_accept_if_voted_by_operator)
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] == "Open", r.body.json()
        proposal_id = r.body.json()["proposal_id"]

        ballot = {"ballot": "function vote (proposal, proposer_id) {{ return true }}"}
        r = c.post(f"/gov/proposals.js/{proposal_id}/ballots", ballot)
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] == "Accepted", r.body.json()

    with node.client(None, "member0") as c:
        r = c.post("/gov/proposals.js", always_accept_if_proposed_by_operator)
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] == "Accepted", r.body.json()
        proposal_id = r.body.json()["proposal_id"]

    return network


@reqs.description("Test actions")
def test_actions(network, args):
    node = network.find_random_node()

    with node.client(None, "member0") as c:
        valid_set_member_data = proposal(
            action(
                "set_member_data",
                member_id=f"{network.consortium.get_member_by_local_id('member0').service_id}",
                member_data={"is_admin": True},
            )
        )

        r = c.post("/gov/proposals.js", valid_set_member_data)
        assert r.status_code == 200, r.body.text()

        valid_rekey_ledger = proposal(action("rekey_ledger"))
        r = c.post("/gov/proposals.js", valid_rekey_ledger)
        assert r.status_code == 200, r.body.text()
    return network


@reqs.description("Test proposal generator")
def test_proposal_generator(network, args):
    restore_js_proposals = prop_gen.GENERATE_JS_PROPOSALS
    prop_gen.GENERATE_JS_PROPOSALS = True

    node = network.find_random_node()
    with node.client(None, "member0") as c:
        proposal, ballot = prop_gen.build_proposal(
            "set_recovery_threshold", {"threshold": 5}
        )
        r = c.post("/gov/proposals.js", proposal)
        assert r.status_code == 200, r.body.text()
        proposal_id = r.body.json()["proposal_id"]

        r = c.post(f"/gov/proposals.js/{proposal_id}/ballots", ballot)
        assert r.status_code == 200, r.body.text()

    prop_gen.GENERATE_JS_PROPOSALS = restore_js_proposals
    return network


@reqs.description("Test apply")
def test_apply(network, args):
    node = network.find_random_node()
    user_to_remove = network.users[-1].service_id
    with node.client(None, "member0") as c:
        r = c.post(
            "/gov/proposals.js",
            proposal(action("remove_user", user_id=user_to_remove)),
        )
        assert r.status_code == 200, r.body.text()
        assert r.body.json()["state"] == "Accepted", r.body.json()

    with node.client(network.users[-1].local_id) as c:
        r = c.get("/app/log/private")
        assert r.status_code == 401, r.body.text()

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_proposal_validation(network, args)
        network = test_proposal_storage(network, args)
        network = test_proposal_withdrawal(network, args)
        network = test_ballot_storage(network, args)
        network = test_pure_proposals(network, args)
        network = test_proposals_with_votes(network, args)
        network = test_operator_proposals_and_votes(network, args)
        network = test_proposal_generator(network, args)
        network = test_apply(network, args)
        network = test_actions(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.package = "liblogging"
    args.nodes = ["local://localhost"]
    args.initial_user_count = 2
    run(args)
