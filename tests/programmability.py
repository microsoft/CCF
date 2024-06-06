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
import { foo } from "./foo.js";

export function content(request) {
    return {
        statusCode: 200,
        body: {
            payload: foo(),
        },
    };
}
"""

FOOJS = """
export function foo() {
    return "Test content";
}
"""


def test_custom_endpoints(network, args):
    primary, _ = network.find_primary()

    # Make user0 admin, so it can install custom endpoints
    user = network.users[0]
    network.consortium.set_user_data(
        primary, user.service_id, user_data={"isAdmin": True}
    )

    content_endpoint_def = {
        "get": {
            "js_module": "test.js",
            "js_function": "content",
            "forwarding_required": "never",
            "redirection_strategy": "none",
            "authn_policies": ["no_auth"],
            "mode": "readonly",
            "openapi": {},
        }
    }

    modules = [
        {"name": "test.js", "module": TESTJS},
        {"name": "foo.js", "module": FOOJS},
    ]

    bundle_with_content = {
        "metadata": {"endpoints": {"/content": content_endpoint_def}},
        "modules": modules,
    }

    bundle_with_other_content = {
        "metadata": {"endpoints": {"/other_content": content_endpoint_def}},
        "modules": modules,
    }

    def test_getters(c, expected_body):
        r = c.get("/app/custom_endpoints")
        assert r.status_code == http.HTTPStatus.OK, r
        assert r.body.json() == body, f"Expected:\n{body}\n\n\nActual:\n{r.body.json()}"

        for module_name, module_content in modules.items():
            r = c.get(f"/app/custom_endpoints/modules/{module_name}")
            assert r.status_code == http.HTTPStatus.OK, r
            assert (
                r.body.text() == module_content
            ), f"Expected:\n{module_content}\n\n\nActual:\n{r.body.text()}"

    with primary.client(None, None, user.local_id) as c:
        r = c.put("/app/custom_endpoints", body=bundle_with_content)
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

        test_getters(c, bundle_with_content)

    with primary.client() as c:
        r = c.get("/app/not_content")
        assert r.status_code == http.HTTPStatus.NOT_FOUND.value, r.status_code

        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        assert r.body.json()["payload"] == "Test content", r.body.json()

    with primary.client(None, None, user.local_id) as c:
        r = c.put("/app/custom_endpoints", body=bundle_with_other_content)
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

        test_getters(c, bundle_with_other_content)

    with primary.client() as c:
        r = c.get("/app/other_content")
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        assert r.body.json()["payload"] == "Test content", r.body.json()

        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.NOT_FOUND.value, r.status_code

    return network


def deploy_npm_app_custom(network, args):
    primary, _ = network.find_nodes()

    # Make user0 admin, so it can install custom endpoints
    user = network.users[0]
    network.consortium.set_user_data(
        primary, user.service_id, user_data={"isAdmin": True}
    )

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

        network = test_custom_endpoints(network, args)

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
