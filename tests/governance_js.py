# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs


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

        r = c.post("/gov/proposals.js", valid_set_recovery_threshold)
        assert r.status_code == 200, r.body.text()
        proposal_id = r.body.json()["proposal_id"]

        r = c.get(f"/gov/proposals.js/{proposal_id}/proposal")
        assert r.status_code == 200, r.body.text()

    return network


@reqs.description("Test ballot storage and validation")
def test_ballot_storage(network, args):
    primary, _ = network.find_nodes()
    valid_set_recovery_threshold = [action("set_recovery_threshold", threshold=5)]

    with primary.client(None, "member0") as c:
        r = c.post("/gov/proposals.js", valid_set_recovery_threshold)
        assert r.status_code == 200, r.body.text()
        pid = r.body.json()["proposal_id"]

        r = c.post(f"/gov/proposals.js/{pid}/votes", {})
        assert r.status_code == 400, r.body.text()

        vote = {"ballot": "function vote (proposal, proposer_id) { return true }"}
        r = c.post(f"/gov/proposals.js/{pid}/votes", vote)
        assert r.status_code == 200, r.body.text()

        member_id = network.consortium.get_member_by_local_id("member0").service_id
        r = c.get(f"/gov/proposals.js/{pid}/votes/{member_id}")
        assert r.status_code == 200, r.body.text()
        assert r.body.text() == f'"{vote["ballot"]}"'

    with primary.client(None, "member1") as c:
        vote = {"ballot": "function vote (proposal, proposer_id) { return false }"}
        r = c.post(f"/gov/proposals.js/{pid}/votes", vote)
        assert r.status_code == 200, r.body.text()

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_proposal_validation(network, args)
        network = test_proposal_storage(network, args)
        # network = test_ballot_storage(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.package = "liblogging"
    args.nodes = ["local://localhost"]
    args.initial_user_count = 1
    run(args)
