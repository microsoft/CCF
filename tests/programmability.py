# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.checker
import infra.jwt_issuer
import infra.proc
import http
import os
import json
from infra.runner import ConcurrentRunner

import npm_tests

from loguru import logger as LOG

TESTJS = """
export function content(request) {
    return {
        statusCode: 200,
        body: {
        payload: "Test content",
        },
    };
}
"""


def endpoint_properties(
    js_module,
    js_function,
    forwarding_required="never",
    redirection_strategy="none",
    mode="readonly",
):
    return {
        "js_module": js_module,
        "js_function": js_function,
        "forwarding_required": forwarding_required,
        "redirection_strategy": redirection_strategy,
        "authn_policies": ["no_auth"],
        "mode": mode,
        "openapi": {},
    }


def test_custom_endpoints(network, args):
    primary, _ = network.find_primary()
    user = network.users[0]

    content_endpoint_def = {
        "get": endpoint_properties(js_module="test.js", js_function="content")
    }

    modules = [{"name": "test.js", "module": TESTJS}]

    bundle_with_content = {
        "metadata": {"endpoints": {"/content": content_endpoint_def}},
        "modules": modules,
    }

    bundle_with_other_content = {
        "metadata": {"endpoints": {"/other_content": content_endpoint_def}},
        "modules": modules,
    }

    with primary.client(None, None, user.local_id) as c:
        r = c.put("/app/custom_endpoints", body=bundle_with_content)
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

    with primary.client() as c:
        r = c.get("/app/not_content")
        assert r.status_code == http.HTTPStatus.NOT_FOUND.value, r.status_code

        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        assert r.body.json()["payload"] == "Test content", r.body.json()

    with primary.client(None, None, user.local_id) as c:
        r = c.put("/app/custom_endpoints", body=bundle_with_other_content)
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

    with primary.client() as c:
        r = c.get("/app/other_content")
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        assert r.body.json()["payload"] == "Test content", r.body.json()

        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.NOT_FOUND.value, r.status_code

    return network


def test_custom_endpoints_kv_restrictions(network, args):
    primary, _ = network.find_primary()
    user = network.users[0]

    module_name = "restrictions.js"

    endpoints = {
        "/try_read": {
            "post": endpoint_properties(
                js_module=module_name,
                js_function="try_read",
            )
        },
        "/try_write": {
            "post": endpoint_properties(
                js_module=module_name,
                js_function="try_write",
                mode="readwrite",
            )
        },
    }

    modules = [
        {
            "name": module_name,
            "module": """
const FIXED_KEY = ccf.strToBuf("hello");
const FIXED_VALUE = ccf.strToBuf("world");

export function try_read(request) {
    const table_name = request.body.json().table;
    var handle;
    try
    {
        handle = ccf.kv[table_name];
    }
    catch (e) {
        return {
            statusCode: 400,
            body: `Failed to get handle for table: ${table_name}\n${e}`
        };
    }

    try
    {
        const v = handle.get(FIXED_KEY);
    }
    catch (e) {
        return {
            statusCode: 400,
            body: `Failed to read from handle for table: ${table_name}\n${e}`
        };
    }

    return {
        statusCode: 200,
        body: `Permitted to read from table: ${table_name}`
    };
}

export function try_write(request) {
    const table_name = request.body.json().table;
    var handle;
    try
    {
        handle = ccf.kv[table_name];
    }
    catch (e) {
        return {
            statusCode: 400,
            body: `Failed to get handle for table: ${table_name}\n${e}`
        };
    }

    try
    {
        handle.set(FIXED_KEY, FIXED_VALUE);
    }
    catch (e) {
        return {
            statusCode: 400,
            body: `Failed to write to handle for table: ${table_name}\n${e}`
        };
    }

    return {
        statusCode: 200,
        body: `Permitted to write to table: ${table_name}`
    };
}
""",
        }
    ]

    bundle_with_content = {
        "metadata": {"endpoints": endpoints},
        "modules": modules,
    }

    with primary.client(None, None, user.local_id) as c:
        r = c.put("/app/custom_endpoints", body=bundle_with_content)
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

    with primary.client() as c:
        LOG.info("Custom table names can be read to and written from")
        r = c.post("/app/try_read", {"table": "my_js_table"})
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        r = c.post("/app/try_write", {"table": "my_js_table"})
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code

        r = c.post("/app/try_read", {"table": "public:my_js_table"})
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        r = c.post("/app/try_write", {"table": "public:my_js_table"})
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code

        LOG.info("'records' is a read-only table")
        r = c.post("/app/try_read", {"table": "records"})
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        r = c.post("/app/try_write", {"table": "records"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code

        LOG.info("'basic.' is a forbidden namespace")
        r = c.post("/app/try_read", {"table": "basic.foo"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code
        r = c.post("/app/try_write", {"table": "basic.foo"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code

        r = c.post("/app/try_read", {"table": "public:basic.foo"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code
        r = c.post("/app/try_write", {"table": "public:basic.foo"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code

    return network


def deploy_npm_app_custom(network, args):
    primary, _ = network.find_nodes()
    user = network.users[0]

    app_dir = os.path.join(npm_tests.THIS_DIR, "npm-app")

    LOG.info("Deploying npm app")
    bundle_path = os.path.join(
        app_dir, "dist", "bundle.json"
    )  # Produced by build_npm_app

    with primary.client(None, None, user.local_id) as c:
        r = c.put(
            "/app/custom_endpoints",
            body=json.load(open(bundle_path)),
        )
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

    return network


def run(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)

        # Make user0 admin, so it can install custom endpoints
        primary, _ = network.find_nodes()
        user = network.users[0]
        network.consortium.set_user_data(
            primary, user.service_id, user_data={"isAdmin": True}
        )

        network = test_custom_endpoints(network, args)
        network = test_custom_endpoints_kv_restrictions(network, args)

        network = npm_tests.build_npm_app(network, args)
        network = deploy_npm_app_custom(network, args)
        network = npm_tests.test_npm_app(network, args)


if __name__ == "__main__":
    cr = ConcurrentRunner()

    cr.add(
        "basic",
        run,
        package="samples/apps/basic/libbasic",
        js_app_bundle=None,
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),
        initial_user_count=2,
        initial_member_count=1,
    )

    cr.run()
