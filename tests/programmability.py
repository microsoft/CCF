# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.checker
import infra.jwt_issuer
import infra.proc
import http
from infra.runner import ConcurrentRunner


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

    modules = {"test.js": TESTJS, "foo.js": FOOJS}

    bundle_with_content = {
        "metadata": {"endpoints": {"/content": content_endpoint_def}},
        "modules": modules,
    }

    bundle_with_other_content = {
        "metadata": {"endpoints": {"/other_content": content_endpoint_def}},
        "modules": modules,
    }

    with primary.client(None, None, user.local_id) as c:
        r = c.put("/app/custom_endpoints", body={"bundle": bundle_with_content})
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

    with primary.client() as c:
        r = c.get("/app/not_content")
        assert r.status_code == http.HTTPStatus.NOT_FOUND.value, r.status_code

        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        assert r.body.json()["payload"] == "Test content", r.body.json()

    with primary.client(None, None, user.local_id) as c:
        r = c.put("/app/custom_endpoints", body={"bundle": bundle_with_other_content})
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

    with primary.client() as c:
        r = c.get("/app/other_content")
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        assert r.body.json()["payload"] == "Test content", r.body.json()

        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.NOT_FOUND.value, r.status_code

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

        test_custom_endpoints(network, args)


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
