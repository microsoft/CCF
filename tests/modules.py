# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import tempfile
import http
import subprocess
import os
import glob
import infra.network
import infra.path
import infra.proc
import infra.notification
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs
import ccf.proposal_generator

from loguru import logger as LOG

THIS_DIR = os.path.dirname(__file__)

MODULE_PATH_1 = "/app/foo.js"
MODULE_RETURN_1 = "Hello world!"
MODULE_CONTENT_1 = f"""
export function foo() {{
    return "{MODULE_RETURN_1}";
}}
"""

MODULE_PATH_2 = "/app/bar.js"
MODULE_CONTENT_2 = """
import {foo} from "./foo.js"
export function bar() {
    return foo();
}
"""

# For the purpose of resolving relative import paths,
# app script modules are currently assumed to be located at /.
# This will likely change.
APP_SCRIPT = """
return {
  ["POST test_module"] = [[
    import {bar} from "./app/bar.js";
    export default function()
    {
      return bar();
    }
  ]]
}
"""

# Eventually, the npm app will contain these modules as well
# together with an API description.
NPM_APP_SCRIPT = """
return {
  ["POST npm/partition"] = [[
    import {partition} from "./my-npm-app/src/endpoints.js";
    export default () => partition();
  ]],
  ["POST npm/proto"] = [[
    import {proto} from "./my-npm-app/src/endpoints.js";
    export default () => proto();
  ]],
  ["GET npm/crypto"] = [[
    import {crypto} from "./my-npm-app/src/endpoints.js";
    export default () => crypto();
  ]]
}
"""


def make_module_set_proposal(path, content, network):
    primary, _ = network.find_nodes()
    with tempfile.NamedTemporaryFile("w") as f:
        f.write(content)
        f.flush()
        proposal_body, _ = ccf.proposal_generator.set_module(path, f.name)
    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )
    network.consortium.vote_using_majority(primary, proposal)


@reqs.description("Test module set and remove")
def test_module_set_and_remove(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Member makes a module update proposal")
    make_module_set_proposal(MODULE_PATH_1, MODULE_CONTENT_1, network)

    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post("/gov/read", {"table": "ccf.modules", "key": MODULE_PATH_1})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body["js"] == MODULE_CONTENT_1, r.body

    LOG.info("Member makes a module remove proposal")
    proposal_body, _ = ccf.proposal_generator.remove_module(MODULE_PATH_1)
    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )
    network.consortium.vote_using_majority(primary, proposal)

    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post("/gov/read", {"table": "ccf.modules", "key": MODULE_PATH_1})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code
    return network


@reqs.description("Test module import")
def test_module_import(network, args):
    primary, _ = network.find_nodes()

    # Add modules
    make_module_set_proposal(MODULE_PATH_1, MODULE_CONTENT_1, network)
    make_module_set_proposal(MODULE_PATH_2, MODULE_CONTENT_2, network)

    # Update JS app which imports module
    with tempfile.NamedTemporaryFile("w") as f:
        f.write(APP_SCRIPT)
        f.flush()
        network.consortium.set_js_app(remote_node=primary, app_script_path=f.name)

    with primary.client("user0") as c:
        r = c.post("/app/test_module", {})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body == MODULE_RETURN_1

    return network


@reqs.description("Test Node.js/npm app")
def test_npm_app(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Building npm app")
    app_dir = os.path.join(THIS_DIR, "npm-app")
    subprocess.run(["npm", "ci"], cwd=app_dir, check=True)
    subprocess.run(["npm", "run", "build"], cwd=app_dir, check=True)

    LOG.info("Deploying npm app modules")
    kv_prefix = "/my-npm-app"
    dist_dir = os.path.join(app_dir, "dist")
    for module_path in glob.glob(os.path.join(dist_dir, "**", "*.js"), recursive=True):
        module_name = os.path.join(kv_prefix, os.path.relpath(module_path, dist_dir))
        proposal_body, _ = ccf.proposal_generator.set_module(module_name, module_path)
        proposal = network.consortium.get_any_active_member().propose(
            primary, proposal_body
        )
        network.consortium.vote_using_majority(primary, proposal)

    LOG.info("Deploying endpoint script")
    with tempfile.NamedTemporaryFile("w") as f:
        f.write(NPM_APP_SCRIPT)
        f.flush()
        network.consortium.set_js_app(remote_node=primary, app_script_path=f.name)

    LOG.info("Calling npm app endpoints")
    with primary.client("user0") as c:
        body = [1, 2, 3, 4]
        r = c.post("/app/npm/partition", body)
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body == [[1, 3], [2, 4]], r.body

        r = c.post("/app/npm/proto", body)
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        # CCF does not support binary responses yet.
        pb = bytes.fromhex(r.body)
        # We could now decode the protobuf message but given all the machinery
        # involved to make it happen (code generation with protoc) we'll leave it at that.
        assert len(pb) == 14, len(pb)

        r = c.get("/app/npm/crypto")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body["available"], r.body


def run(args):
    hosts = ["localhost"] * (3 if args.consensus == "pbft" else 2)

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_module_set_and_remove(network, args)
        network = test_module_import(network, args)
        network = test_npm_app(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "libjs_generic"
    run(args)
