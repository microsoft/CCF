# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import tempfile
import http
import subprocess
import os
import json
import shutil
from base64 import b64encode
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import infra.crypto
import suite.test_requirements as reqs
import ccf.proposal_generator

from loguru import logger as LOG

THIS_DIR = os.path.dirname(__file__)

MODULE_PREFIX_1 = "/app/"
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
      return { body: bar(), statusCode: 201 };
    }
  ]]
}
"""


def make_module_set_proposal(path, content, network):
    primary, _ = network.find_nodes()
    with tempfile.NamedTemporaryFile("w") as f:
        f.write(content)
        f.flush()
        proposal_body, careful_vote = ccf.proposal_generator.set_module(path, f.name)
    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )
    proposal.vote_for = careful_vote
    network.consortium.vote_using_majority(primary, proposal)


@reqs.description("Test module set and remove")
def test_module_set_and_remove(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Member makes a module set proposal")
    make_module_set_proposal(MODULE_PATH_1, MODULE_CONTENT_1, network)

    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post(
            "/gov/read", {"table": "public:ccf.gov.modules", "key": MODULE_PATH_1}
        )
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body.json()["js"] == MODULE_CONTENT_1, r.body

    LOG.info("Member makes a module remove proposal")
    proposal_body, careful_vote = ccf.proposal_generator.remove_module(MODULE_PATH_1)
    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )
    proposal.vote_for = careful_vote
    network.consortium.vote_using_majority(primary, proposal)

    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post(
            "/gov/read", {"table": "public:ccf.gov.modules", "key": MODULE_PATH_1}
        )
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
        assert r.status_code == http.HTTPStatus.CREATED, r.status_code
        assert r.body.text() == MODULE_RETURN_1

    return network


@reqs.description("Test js app bundle")
def test_app_bundle(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Deploying js app bundle archive")
    # Testing the bundle archive support of the Python client here.
    # Plain bundle folders are tested in the npm-based app tests.
    bundle_dir = os.path.join(THIS_DIR, "js-app-bundle")
    with tempfile.TemporaryDirectory(prefix="ccf") as tmp_dir:
        bundle_path = shutil.make_archive(
            os.path.join(tmp_dir, "bundle"), "zip", bundle_dir
        )
        network.consortium.deploy_js_app(primary, bundle_path)

    LOG.info("Verifying that modules and endpoints were added")
    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post("/gov/read", {"table": "public:ccf.gov.modules", "key": "/math.js"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code

    with primary.client("user0") as c:
        valid_body = {"op": "sub", "left": 82, "right": 40}
        r = c.post("/app/compute", valid_body)
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "application/json"
        assert r.body.json() == {"result": 42}, r.body

        invalid_body = {"op": "add", "left": "1", "right": 2}
        r = c.post("/app/compute", invalid_body)
        assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code
        assert r.headers["content-type"] == "application/json"
        assert r.body.json() == {"error": "invalid operand type"}, r.body

    LOG.info("Removing js app")
    proposal_body, careful_vote = ccf.proposal_generator.remove_js_app()
    proposal = network.consortium.get_any_active_member().propose(
        primary, proposal_body
    )
    proposal.vote_for = careful_vote
    network.consortium.vote_using_majority(primary, proposal)

    LOG.info("Verifying that modules and endpoints were removed")
    with primary.client("user0") as c:
        r = c.post("/app/compute", valid_body)
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code

    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post("/gov/read", {"table": "public:ccf.gov.modules", "key": "/math.js"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST, r.status_code

    return network


@reqs.description("Test dynamically installed endpoint properties")
def test_dynamic_endpoints(network, args):
    primary, _ = network.find_nodes()

    bundle_dir = os.path.join(THIS_DIR, "js-app-bundle")

    LOG.info("Deploying initial js app bundle archive")
    network.consortium.deploy_js_app(primary, bundle_dir)

    valid_body = {"op": "sub", "left": 82, "right": 40}
    expected_response = {"result": 42}

    LOG.info("Checking initial endpoint is accessible")
    with primary.client("user0") as c:
        r = c.post("/app/compute", valid_body)
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "application/json"
        assert r.body.json() == expected_response, r.body

    LOG.info("Checking initial endpoint is inaccessible without auth")
    with primary.client() as c:
        r = c.post("/app/compute", valid_body)
        assert r.status_code == http.HTTPStatus.FORBIDDEN, r.status_code

    LOG.info("Deploying modified js app bundle")
    with tempfile.TemporaryDirectory(prefix="ccf") as tmp_dir:
        modified_bundle_dir = shutil.copytree(bundle_dir, tmp_dir, dirs_exist_ok=True)
        metadata_path = os.path.join(modified_bundle_dir, "app.json")
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
        # Modifying a single entry
        metadata["endpoints"]["/compute"]["post"]["require_client_identity"] = False
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        network.consortium.deploy_js_app(primary, modified_bundle_dir)

    LOG.info("Checking modified endpoint is accessible without auth")
    with primary.client() as c:
        r = c.post("/app/compute", valid_body)
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "application/json"
        assert r.body.json() == expected_response, r.body

    return network


@reqs.description("Test basic Node.js/npm app")
def test_npm_app(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Building npm app")
    app_dir = os.path.join(THIS_DIR, "npm-app")
    subprocess.run(["npm", "install"], cwd=app_dir, check=True)
    subprocess.run(["npm", "run", "build"], cwd=app_dir, check=True)

    LOG.info("Deploying npm app")
    bundle_dir = os.path.join(app_dir, "dist")
    network.consortium.deploy_js_app(primary, bundle_dir)

    LOG.info("Calling npm app endpoints")
    with primary.client("user0") as c:
        body = [1, 2, 3, 4]
        r = c.post("/app/partition", body)
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body.json() == [[1, 3], [2, 4]], r.body

        r = c.post("/app/proto", body)
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "application/x-protobuf"
        # We could now decode the protobuf message but given all the machinery
        # involved to make it happen (code generation with protoc) we'll leave it at that.
        assert len(r.body) == 14, len(r.body)

        r = c.get("/app/crypto")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body.json()["available"], r.body

        key_size = 256
        r = c.post("/app/generateAesKey", {"size": key_size})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert len(r.body.data()) == key_size // 8
        assert r.body.data() != b"\x00" * (key_size // 8)

        aes_key_to_wrap = infra.crypto.generate_aes_key(256)
        wrapping_key_priv_pem, wrapping_key_pub_pem = infra.crypto.generate_rsa_keypair(
            2048
        )
        label = "label42"
        r = c.post(
            "/app/wrapKeyRsaOaep",
            {
                "key": b64encode(aes_key_to_wrap).decode(),
                "wrappingKey": wrapping_key_pub_pem,
                "label": label,
            },
        )
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        unwrapped = infra.crypto.unwrap_key_rsa_oaep(
            r.body.data(), wrapping_key_priv_pem, label.encode("ascii")
        )
        assert unwrapped == aes_key_to_wrap

        r = c.get("/app/log?id=42")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code

        r = c.post("/app/log?id=42", {"msg": "Hello!"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code

        r = c.get("/app/log?id=42")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        body = r.body.json()
        assert body["msg"] == "Hello!", r.body

    return network


@reqs.description("Test tsoa-based Node.js/npm app")
def test_npm_tsoa_app(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Building tsoa npm app")
    app_dir = os.path.join(THIS_DIR, "npm-tsoa-app")
    subprocess.run(["npm", "install"], cwd=app_dir, check=True)
    subprocess.run(["npm", "run", "build"], cwd=app_dir, check=True)

    LOG.info("Deploying tsoa npm app")
    bundle_dir = os.path.join(app_dir, "dist")
    network.consortium.deploy_js_app(primary, bundle_dir)

    LOG.info("Calling tsoa npm app endpoints")
    with primary.client("user0") as c:
        body = [1, 2, 3, 4]
        r = c.post("/app/partition", body)
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body.json() == [[1, 3], [2, 4]], r.body

        r = c.post("/app/proto", body)
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "application/x-protobuf"
        # We could now decode the protobuf message but given all the machinery
        # involved to make it happen (code generation with protoc) we'll leave it at that.
        assert len(r.body) == 14, len(r.body)

        r = c.get("/app/crypto")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body.json()["available"], r.body

    return network


def run(args):
    hosts = ["localhost"] * (3 if args.consensus == "bft" else 2)

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_module_set_and_remove(network, args)
        network = test_module_import(network, args)
        network = test_app_bundle(network, args)
        network = test_dynamic_endpoints(network, args)
        network = test_npm_app(network, args)
        network = test_npm_tsoa_app(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "libjs_generic"
    run(args)
