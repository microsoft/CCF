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


@reqs.description("Test proposals")
def test_proposals(network, args):
    primary, _ = network.find_nodes()
    add_member = [action("add_member", cert="", enc_pubk="", member_data={})]

    valid_set_recovery_threshold = [action("set_recovery_threshold", threshold=5)]
    no_args_set_recovery_threshold = [action("set_recovery_threshold")]
    bad_arg_set_recovery_threshold = [action("set_recovery_threshold", threshold=5000)]

    with primary.client(None, "member0") as c:
        r = c.post("/gov/proposals.js", valid_set_recovery_threshold)
        assert r.status_code == 200, r.body.text()

    with primary.client(None, "member0") as c:
        r = c.post("/gov/proposals.js", valid_set_recovery_threshold * 2)
        assert r.status_code == 200, r.body.text()

    with primary.client(None, "member0") as c:
        r = c.post("/gov/proposals.js", no_args_set_recovery_threshold)
        assert r.status_code == 400 and r.body.json()["error"]["code"] == "ProposalFailedToValidate", r.body.text()

    with primary.client(None, "member0") as c:
        r = c.post("/gov/proposals.js", no_args_set_recovery_threshold + bad_arg_set_recovery_threshold)
        assert r.status_code == 400 and r.body.json()["error"]["code"] == "ProposalFailedToValidate", r.body.text()

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_proposals(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()

    args.package = "liblogging"
    args.nodes = ["local://localhost"]
    args.initial_user_count = 3
    run(args)
