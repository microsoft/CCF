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

    with primary.client(None, "member0") as c:
        c.post("/gov/proposals.js", add_member)

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
