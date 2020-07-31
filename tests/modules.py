# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
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

MODULE_RETURN = "Hello world!"
MODULE_CONTENT = f"""
export function foo() {{
    return "{MODULE_RETURN}";
}}
"""

APP_SCRIPT = """
return {
  ["POST test_module"] = [[
    import {foo} from "foo.js";
    export default function()
    {
      return foo();
    }
  ]]
}
"""


@reqs.description("Test module set and remove")
def test_module_set_and_remove(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Member makes a module update proposal")
    with tempfile.NamedTemporaryFile("w") as f:
        f.write(MODULE_CONTENT)
        f.flush()
        proposal_body, _ = ccf.proposal_generator.set_module("foo.js", f.name)
    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )
    network.consortium.vote_using_majority(primary, proposal)

    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post("/gov/read", {"table": "ccf.modules", "key": "foo.js"})
        assert r.status_code == 200, r.status_code
        assert r.body["js"] == MODULE_CONTENT, r.body

    LOG.info("Member makes a module remove proposal")
    proposal_body, _ = ccf.proposal_generator.remove_module("foo.js")
    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )
    network.consortium.vote_using_majority(primary, proposal)

    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post("/gov/read", {"table": "ccf.modules", "key": "foo.js"})
        assert r.status_code == 400, r.status_code

    return network


@reqs.description("Test module import")
def test_module_import(network, args):
    primary, _ = network.find_nodes()

    # Add module
    with tempfile.NamedTemporaryFile("w") as f:
        f.write(MODULE_CONTENT)
        f.flush()
        proposal_body, _ = ccf.proposal_generator.set_module("foo.js", f.name)
    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )
    network.consortium.vote_using_majority(primary, proposal)

    # Update JS app which imports module
    with tempfile.NamedTemporaryFile("w") as f:
        f.write(APP_SCRIPT)
        f.flush()
        network.consortium.set_js_app(remote_node=primary, app_script_path=f.name)

    with primary.client("user0") as c:
        r = c.post("/app/test_module", {})
        assert r.status_code == 200, r.status_code
        assert r.body == MODULE_RETURN

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
