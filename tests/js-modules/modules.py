# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import tempfile
import http
import os
import json
import shutil
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import infra.crypto
import suite.test_requirements as reqs
import urllib.parse
from e2e_logging import test_multi_auth

from npm_tests import build_npm_app, deploy_npm_app, test_npm_app, validate_openapi

from loguru import logger as LOG

THIS_DIR = os.path.dirname(__file__)
PARENT_DIR = os.path.normpath(os.path.join(THIS_DIR, os.path.pardir))


@reqs.description("Test module import")
def test_module_import(network, args):
    primary, _ = network.find_nodes()

    # Update JS app, deploying modules _and_ app script that imports module
    bundle_dir = os.path.join(THIS_DIR, "basic-module-import")
    network.consortium.set_js_app_from_dir(primary, bundle_dir)

    with primary.client("user0") as c:
        r = c.post("/app/test_module", {})
        assert r.status_code == http.HTTPStatus.CREATED, r.status_code
        assert r.body.text() == "Hello world!"

    return network


def compare_app_metadata(expected, actual, api_key_renames, route=[]):
    path = ".".join(route)
    assert isinstance(
        actual, type(actual)
    ), f"Expected same type of values at {path}, found {type(expected)} vs {type(actual)}"

    if isinstance(expected, dict):
        for orig_k, v_expected in expected.items():
            k = orig_k
            if k in api_key_renames:
                k = api_key_renames[k]

            assert (
                k in actual
            ), f"Expected key {k} (normalised from {orig_k}) at {path}, found: {actual}"
            v_actual = actual[k]

            compare_app_metadata(v_expected, v_actual, api_key_renames, route + [k])
    else:
        if not isinstance(expected, list) and expected in api_key_renames:
            k = api_key_renames[expected]
            assert (
                k == actual
            ), f"Mismatch at {path}, expected {k} (normalised from {expected}) and found {actual}"
        else:
            assert (
                expected == actual
            ), f"Mismatch at {path}, expected {expected} and found {actual}"


def canonicalise(orig, renames):
    if isinstance(orig, dict):
        o = {}
        for k, v in orig.items():
            if k in renames:
                k = renames[k]
            o[k] = canonicalise(v, renames)
        return o
    elif isinstance(orig, str) and orig in renames:
        return renames[orig]
    else:
        return orig


@reqs.description("Test module access")
def test_module_access(network, args):
    primary, _ = network.find_nodes()

    bundle_dir = os.path.join(THIS_DIR, "basic-module-import")
    bundle = network.consortium.read_bundle_from_dir(bundle_dir)
    network.consortium.set_js_app_from_bundle(primary, bundle)

    expected_modules = bundle["modules"]
    expected_metadata = bundle["metadata"]

    http_methods_renamed = {
        method: method.upper() for method in ("post", "get", "put", "delete")
    }
    module_names_prefixed = {
        module["name"]: f"/{module['name']}"
        for module in expected_modules
        if not module["name"].startswith("/")
    }
    endpoint_def_camelcased = {
        "js_module": "jsModule",
        "js_function": "jsFunction",
        "forwarding_required": "forwardingRequired",
        "redirection_strategy": "redirectionStrategy",
        "authn_policies": "authnPolicies",
        "openapi": "openApi",
    }

    with primary.api_versioned_client(api_version=args.gov_api_version) as c:
        # The response with ?case=original should be almost exactly what was
        # submitted (including exactly which fields are present/omitted). The
        # only changes are the casing of HTTP verbs, and the prefixing of module
        # names.
        r = c.get("/gov/service/javascript-app?case=original")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        actual = r.body.json()
        expected = canonicalise(
            expected_metadata,
            {
                **http_methods_renamed,
                **module_names_prefixed,
            },
        )
        assert (
            expected == actual
        ), f"{json.dumps(expected, indent=2)}\nvs\n{json.dumps(actual, indent=2)}"

        r = c.get("/gov/service/javascript-app")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        compare_app_metadata(
            expected_metadata,
            r.body.json(),
            {
                **http_methods_renamed,
                **module_names_prefixed,
                **endpoint_def_camelcased,
            },
        )

        r = c.get("/gov/service/javascript-modules")
        assert r.status_code == http.HTTPStatus.OK, r.status_code

        modules = [e["moduleName"] for e in r.body.json()["value"]]

        assert len(modules) == len(expected_modules)

        for module_def in expected_modules:
            raw_name = module_def["name"]
            norm_name = f"/{raw_name}"

            assert norm_name in modules, f"{norm_name} not in {modules}"

            r = c.get(
                f"/gov/service/javascript-modules/{urllib.parse.quote_plus(norm_name)}"
            )
            assert r.status_code == http.HTTPStatus.OK, r

            content = r.body.text()
            assert content == module_def["module"]

    return network


@reqs.description("Test module bytecode caching")
@reqs.installed_package("js_generic")
def test_bytecode_cache(network, args):
    primary, _ = network.find_nodes()

    bundle_dir = os.path.join(THIS_DIR, "basic-module-import")

    LOG.info("Verifying that app works without bytecode cache")
    network.consortium.set_js_app_from_dir(
        primary, bundle_dir, disable_bytecode_cache=True
    )

    with primary.client("user0") as c:
        r = c.get("/node/js_metrics")
        body = r.body.json()
        assert body["bytecode_size"] == 0, "Module bytecode exists but should not"
        assert not body["bytecode_used"], body

    with primary.client("user0") as c:
        r = c.post("/app/test_module", {})
        assert r.status_code == http.HTTPStatus.CREATED, r.status_code
        assert r.body.text() == "Hello world!"

    LOG.info("Verifying that app works with bytecode cache")
    network.consortium.set_js_app_from_dir(
        primary, bundle_dir, disable_bytecode_cache=False
    )

    with primary.client("user0") as c:
        r = c.get("/node/js_metrics")
        body = r.body.json()
        assert body["bytecode_size"] > 0, "Module bytecode is missing"
        assert body["bytecode_used"], body

    with primary.client("user0") as c:
        r = c.post("/app/test_module", {})
        assert r.status_code == http.HTTPStatus.CREATED, r.status_code
        assert r.body.text() == "Hello world!"

    LOG.info("Verifying that redeploying app cleans bytecode cache")
    network.consortium.set_js_app_from_dir(
        primary, bundle_dir, disable_bytecode_cache=True
    )

    with primary.client("user0") as c:
        r = c.get("/node/js_metrics")
        body = r.body.json()
        assert body["bytecode_size"] == 0, "Module bytecode exists but should not"
        assert not body["bytecode_used"], body

    LOG.info(
        "Verifying that bytecode cache can be enabled/refreshed without app re-deploy"
    )
    network.consortium.refresh_js_app_bytecode_cache(primary)

    with primary.client("user0") as c:
        r = c.get("/node/js_metrics")
        body = r.body.json()
        assert body["bytecode_size"] > 0, "Module bytecode is missing"
        assert body["bytecode_used"], body

    with primary.client("user0") as c:
        r = c.post("/app/test_module", {})
        assert r.status_code == http.HTTPStatus.CREATED, r.status_code
        assert r.body.text() == "Hello world!"

    return network


@reqs.description("Test js runtime options")
def test_set_js_runtime(network, args):
    primary, _ = network.find_nodes()
    # set js run time options
    network.consortium.set_js_runtime_options(
        primary,
        max_heap_bytes=50 * 1024 * 1024,
        max_stack_bytes=1024 * 512,
        max_execution_time_ms=500,
    )
    with primary.client("user0") as c:
        r = c.get("/node/js_metrics")
        body = r.body.json()
        assert body["max_heap_size"] == 50 * 1024 * 1024
        assert body["max_stack_size"] == 1024 * 512
        assert body["max_execution_time"] == 500
    # reset the heap and stack sizes to default values
    network.consortium.set_js_runtime_options(
        primary,
        max_heap_bytes=100 * 1024 * 1024,
        max_stack_bytes=1024 * 1024,
        max_execution_time_ms=1000,
    )
    return network


@reqs.description("Test js app bundle")
def test_app_bundle(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Deploying js app bundle archive")
    # Testing the bundle archive support of the Python client here.
    # Plain bundle folders are tested in the npm-based app tests.
    bundle_dir = os.path.join(PARENT_DIR, "js-app-bundle")
    raw_module_name = "/math.js".encode()
    with tempfile.TemporaryDirectory(prefix="ccf") as tmp_dir:
        bundle_path = shutil.make_archive(
            os.path.join(tmp_dir, "bundle"), "zip", bundle_dir
        )
        set_js_proposal = network.consortium.set_js_app_from_dir(primary, bundle_path)

        assert (
            raw_module_name
            in network.get_ledger_public_state_at(set_js_proposal.completed_seqno)[
                "public:ccf.gov.modules"
            ]
        ), "Module was not added"

    LOG.info("Verifying that app was deployed")

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

        validate_openapi(c)

    LOG.info("Removing js app")
    remove_js_proposal = network.consortium.remove_js_app(primary)

    LOG.info("Verifying that modules and endpoints were removed")
    with primary.client("user0") as c:
        r = c.post("/app/compute", valid_body)
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code

    assert (
        network.get_ledger_public_state_at(remove_js_proposal.completed_seqno)[
            "public:ccf.gov.modules"
        ][raw_module_name]
        is None
    ), "Module was not removed"

    return network


@reqs.description("Test dynamically installed endpoint properties")
def test_dynamic_endpoints(network, args):
    primary, _ = network.find_nodes()

    bundle_dir = os.path.join(PARENT_DIR, "js-app-bundle")

    LOG.info("Deploying initial js app bundle archive")
    network.consortium.set_js_app_from_dir(primary, bundle_dir)

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
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED, r.status_code

    LOG.info("Checking templated endpoint is accessible")
    with primary.client("user0") as c:
        r = c.get("/app/compute2/mul/5/7")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "application/json"
        assert r.body.json()["result"] == 35, r.body.json()

    LOG.info("Deploying modified js app bundle")
    with tempfile.TemporaryDirectory(prefix="ccf") as tmp_dir:
        modified_bundle_dir = shutil.copytree(bundle_dir, tmp_dir, dirs_exist_ok=True)
        metadata_path = os.path.join(modified_bundle_dir, "app.json")
        with open(metadata_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)
        # Modifying a single entry
        metadata["endpoints"]["/compute"]["post"]["authn_policies"] = []
        # Adding new paths with ambiguous conflicting templates
        metadata["endpoints"]["/dispatch_test/{bar}"] = metadata["endpoints"][
            "/compute"
        ]
        metadata["endpoints"]["/dispatch_test/{baz}"] = metadata["endpoints"][
            "/compute"
        ]
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
        network.consortium.set_js_app_from_dir(primary, modified_bundle_dir)

    LOG.info("Checking modified endpoint is accessible without auth")
    with primary.client() as c:
        r = c.post("/app/compute", valid_body)
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "application/json"
        assert r.body.json() == expected_response, r.body

    LOG.info("Checking ambiguous templates cause a dispatch error")
    with primary.client("user0") as c:
        r = c.post("/app/dispatch_test/foo")
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r.status_code
        body = r.body.json()
        msg = body["error"]["message"]
        assert "/foo" in msg, body
        assert "/{bar}" in msg, body
        assert "/{baz}" in msg, body

    return network


@reqs.description("Test JS execution time out with npm app endpoint")
def test_js_execution_time(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Deploying npm app")
    app_dir = os.path.join(PARENT_DIR, "npm-app")
    bundle_path = os.path.join(
        app_dir, "dist", "bundle.json"
    )  # Produced by build_npm_app
    bundle = infra.consortium.slurp_json(bundle_path)
    network.consortium.set_js_app_from_bundle(primary, bundle)

    with primary.client("user0") as c:
        # fetch defaults from js_metrics endpoint
        r = c.get("/node/js_metrics")
        body = r.body.json()
        default_max_heap_size = body["max_heap_size"]
        default_max_stack_size = body["max_stack_size"]
        default_max_execution_time = body["max_execution_time"]

        # set JS execution time to a lower value which will timeout this
        # endpoint execution
        network.consortium.set_js_runtime_options(
            primary,
            max_heap_bytes=50 * 1024 * 1024,
            max_stack_bytes=1024 * 512,
            max_execution_time_ms=1,
        )

        surely_will_time_out = 123456789
        r = c.post("/app/spin", {"iterations": surely_will_time_out})

        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r.status_code
        body = r.body.json()
        assert body["error"]["message"] == "Operation took too long to complete."

        # reset the execution time
        network.consortium.set_js_runtime_options(
            primary,
            max_heap_bytes=default_max_heap_size,
            max_stack_bytes=default_max_stack_size,
            max_execution_time_ms=default_max_execution_time,
        )

        r = c.post("/app/spin", {"iterations": 1})

        assert r.status_code == http.HTTPStatus.OK, r.status_code

    return network


@reqs.description("Test JS exception output")
def test_js_exception_output(network, args):
    network = deploy_npm_app(network, args)

    primary, _ = network.find_nodes()

    with primary.client("user0") as c:
        r = c.get("/node/js_metrics")
        body = r.body.json()
        default_max_heap_size = body["max_heap_size"]
        default_max_stack_size = body["max_stack_size"]
        default_max_execution_time = body["max_execution_time"]

        r = c.get("/app/throw")
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r.status_code
        body = r.body.json()
        assert body["error"]["code"] == "InternalError"
        assert body["error"]["message"] == "Exception thrown while executing."
        assert "details" not in body["error"]

        network.consortium.set_js_runtime_options(
            primary,
            max_heap_bytes=default_max_heap_size,
            max_stack_bytes=default_max_stack_size,
            max_execution_time_ms=default_max_execution_time,
            return_exception_details=True,
        )
        r = c.get("/app/throw")
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r.status_code
        body = r.body.json()
        assert body["error"]["code"] == "InternalError"
        assert body["error"]["message"] == "Exception thrown while executing."
        assert body["error"]["details"][0]["code"] == "JSException"
        assert body["error"]["details"][0]["message"] == "Error: test error: 42"
        assert (
            body["error"]["details"][0]["trace"]
            == "    at nested (/endpoints/rpc.js:27)\n    at throwError (/endpoints/rpc.js:29)\n"
        )

        network.consortium.set_js_runtime_options(
            primary,
            max_heap_bytes=default_max_heap_size,
            max_stack_bytes=default_max_stack_size,
            max_execution_time_ms=default_max_execution_time,
            return_exception_details=False,
        )

        r = c.get("/app/throw")
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r.status_code
        body = r.body.json()
        assert body["error"]["code"] == "InternalError"
        assert body["error"]["message"] == "Exception thrown while executing."
        assert "details" not in body["error"]

        network.consortium.set_js_runtime_options(
            primary,
            max_heap_bytes=default_max_heap_size,
            max_stack_bytes=default_max_stack_size,
            max_execution_time_ms=default_max_execution_time,
            log_exception_details=True,
        )

        r = c.get("/app/throw")
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r.status_code
        body = r.body.json()
        assert body["error"]["code"] == "InternalError"
        assert body["error"]["message"] == "Exception thrown while executing."
        assert "details" not in body["error"]

    return network


@reqs.description("Test User Cose authentication")
def test_user_cose_authentication(network, args):
    primary, _ = network.find_nodes()

    with primary.client() as c:
        r = c.put("/app/cose", {})
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED, r

    with primary.client("user0") as c:
        r = c.put("/app/cose", {})
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED, r

    with primary.client("user0", headers={"content-type": "application/cose"}) as c:
        r = c.put("/app/cose", {})
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r

    with primary.client(None, None, "user0") as c:
        r = c.put("/app/cose", body={"some": "content"})
        assert r.status_code == http.HTTPStatus.OK, r
        body = r.body.json()
        assert body["policy"] == "user_cose_sign1"
        assert body["id"] == network.users[0].service_id

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        # Needs to happen early, so later tests can deploy it if they want to
        network = build_npm_app(network, args)

        # Needs to happen before any other call to set_js_runtime_options
        # to properly test the default values, which should not emit
        # error details on response (or in the log).
        network = test_js_exception_output(network, args)

        network = test_module_import(network, args)
        network = test_module_access(network, args)
        network = test_bytecode_cache(network, args)
        network = test_app_bundle(network, args)
        network = test_dynamic_endpoints(network, args)
        network = test_set_js_runtime(network, args)

        # Remaining tests all require this app, and its endpoints
        network = deploy_npm_app(network, args)

        network = test_npm_app(network, args)
        network = test_js_execution_time(network, args)
        network = test_user_cose_authentication(network, args)
        network = test_multi_auth(network, args)


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.initial_user_count = 2
    args.initial_member_count = 2
    run(args)
