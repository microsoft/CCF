# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import sys
import tempfile
import infra.network
import infra.path
import infra.proc
import infra.notification
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs
import ccf.proposal_generator

from loguru import logger as LOG

MODULE_CONTENT = """
export default function() {
    return "Hello world!";
}
"""

APP_SCRIPT = """
return {
  ["GET myapp/test_module"] = [[
    import default_fn from "foo.js";
    return function()
    {
      return default_fn();
    }()
  ]]
}
"""

@reqs.description("Test module set and remove")
def test_module_set_and_remove(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Member makes a module update proposal")
    with tempfile.NamedTemporaryFile('w') as f:
        f.write(MODULE_CONTENT)
        f.flush()
        proposal_body, _ = ccf.proposal_generator.set_module("foo.js", f.name)
    proposal = network.consortium.get_any_active_member().propose(primary, proposal_body)
    network.consortium.vote_using_majority(primary, proposal)
    
    with primary.client(f"member{network.consortium.get_any_active_member().member_id}") as c:
        r = c.post(
            "/gov/read", {"table": "ccf.modules", "key": "foo.js"}
        )
        assert r.status == 200, r.status
        assert r.body['js'] == MODULE_CONTENT, r.body

    LOG.info("Member makes a module remove proposal")
    proposal_body, _ = ccf.proposal_generator.remove_module("foo.js")
    proposal = network.consortium.get_any_active_member().propose(primary, proposal_body)
    network.consortium.vote_using_majority(primary, proposal)

    with primary.client(f"member{network.consortium.get_any_active_member().member_id}") as c:
        r = c.post(
            "/gov/read", {"table": "ccf.modules", "key": "foo.js"}
        )
        assert r.status == 400, r.status

    return network

@reqs.description("Test module import")
def test_module_import(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Member makes a module update proposal")
    with tempfile.NamedTemporaryFile('w') as f:
        f.write(MODULE_CONTENT)
        f.flush()
        proposal_body, _ = ccf.proposal_generator.set_module("foo.js", f.name)
    proposal = network.consortium.get_any_active_member().propose(primary, proposal_body)
    network.consortium.vote_using_majority(primary, proposal)

    # TODO set app script

    # TODO invoke endpoint
    # TODO check return value

    return network

def run(args):
    hosts = ["localhost"] * (3 if args.consensus == "pbft" else 2)

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_module_set_and_remove(network, args)
        network = test_module_import(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "libjs_generic"
    run(args)
