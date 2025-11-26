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
from governance_js import action, proposal, ballot_yes
import ccf.cose
import infra.clients

import npm_tests
import jwt_test

from loguru import logger as LOG

TESTJS = """
import { foo } from "./bar/baz.js";

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

TESTJS_ROLE = """
export function content(request) {
  console.log(`my_constant is: ${my_object.my_constant}`);
  
  const endpoint_name = request.url.split("/")[2];
  const action_name = `/${endpoint_name}/read`;
  const permitted = my_object.hasRole(request.caller.id, action_name);
  if (permitted)
  {
    return {
        statusCode: 200,
        body: {
            payload: "Test content",
        },
    };
  }

  return {
    statusCode: 403
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


def sign_payload(identity, msg_type, json_payload):
    serialised_payload = json.dumps(json_payload).encode()
    key = open(identity.key, "r").read()
    cert = open(identity.cert, "r").read()
    phdr = {
        "app.msg.type": msg_type,
        "app.msg.created_at": int(infra.clients.get_clock().moment().timestamp()),
    }

    return ccf.cose.create_cose_sign1(serialised_payload, key, cert, phdr)


def test_custom_endpoints(network, args):
    primary, _ = network.find_primary()
    user = network.users[0]

    content_endpoint_def = {
        "get": endpoint_properties(js_module="test.js", js_function="content")
    }

    modules = [
        {"name": "test.js", "module": TESTJS},
        {"name": "bar/baz.js", "module": FOOJS},
    ]

    bundle_with_content = {
        "metadata": {"endpoints": {"/content": content_endpoint_def}},
        "modules": modules,
    }

    bundle_with_other_content = {
        "metadata": {"endpoints": {"/other_content": content_endpoint_def}},
        "modules": modules,
    }

    def upper_cased_keys(obj):
        return {k.upper(): v for k, v in obj.items()}

    def prefixed_module_name(module_def):
        if module_def["name"].startswith("/"):
            return module_def
        else:
            return {**module_def, "name": f"/{module_def['name']}"}

    def same_modulo_normalisation(expected, actual):
        # Normalise expected (in the same way that CCF will) so we can do direct comparison
        expected["metadata"]["endpoints"] = {
            path: upper_cased_keys(op)
            for path, op in expected["metadata"]["endpoints"].items()
        }
        expected["modules"] = [
            prefixed_module_name(module_def) for module_def in expected["modules"]
        ]
        return expected == actual

    def test_getters(c, expected_body):
        r = c.get("/app/custom_endpoints")
        assert r.status_code == http.HTTPStatus.OK, r
        assert same_modulo_normalisation(
            expected_body, r.body.json()
        ), f"Expected:\n{expected_body}\n\n\nActual:\n{r.body.json()}"

        for module_def in modules:
            r = c.get(f"/app/custom_endpoints/modules?module_name={module_def['name']}")
            assert r.status_code == http.HTTPStatus.OK, r
            assert (
                r.body.text() == module_def["module"]
            ), f"Expected:\n{module_def['module']}\n\n\nActual:\n{r.body.text()}"

    signed_bundle = sign_payload(
        network.identity(user.local_id), "custom_endpoints", bundle_with_content
    )
    with primary.client() as c:
        r = c.put(
            "/app/custom_endpoints",
            body=signed_bundle,
            headers={"Content-Type": "application/cose"},
        )
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code
        test_getters(c, bundle_with_content)

    # Install also works with cert authentication, at the expense of potential offline
    # auditability, since the ledger will not contain a signature
    with primary.client(user.local_id, None, None) as c:
        r = c.put("/app/custom_endpoints", body=bundle_with_content)
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

    with primary.client() as c:
        r = c.get("/app/not_content")
        assert r.status_code == http.HTTPStatus.NOT_FOUND.value, r.status_code

        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        assert r.body.json()["payload"] == "Test content", r.body.json()

    signed_bundle = sign_payload(
        network.identity(user.local_id), "custom_endpoints", bundle_with_other_content
    )
    with primary.client() as c:
        r = c.put(
            "/app/custom_endpoints",
            body=signed_bundle,
            headers={"Content-Type": "application/cose"},
        )
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

        test_getters(c, bundle_with_other_content)

    with primary.client() as c:
        r = c.get("/app/other_content")
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        assert r.body.json()["payload"] == "Test content", r.body.json()

        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.NOT_FOUND.value, r.status_code

    return network


def test_custom_endpoints_circular_includes(network, args):
    primary, _ = network.find_primary()
    user = network.users[0]

    MODULE_A_NAME = "a.js"
    MODULE_B_NAME = "b.js"
    modules = [
        {
            "name": MODULE_A_NAME,
            "module": """
import "b.js";

export function do_op(request) {
    return {
        statusCode: 204
    };
}
""",
        },
        {
            "name": MODULE_B_NAME,
            "module": """import "a.js";""",
        },
    ]

    recursive_bundle = {
        "metadata": {
            "endpoints": {
                "/do_op": {
                    "get": endpoint_properties(
                        js_module=MODULE_A_NAME, js_function="do_op"
                    )
                }
            }
        },
        "modules": modules,
    }

    signed_bundle = sign_payload(
        network.identity(user.local_id), "custom_endpoints", recursive_bundle
    )
    with primary.client() as c:
        r = c.put(
            "/app/custom_endpoints",
            body=signed_bundle,
            headers={"Content-Type": "application/cose"},
        )
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

    with primary.client() as c:
        r = c.get("/app/do_op")
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

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
            "module": open(
                os.path.join(
                    os.path.dirname(__file__), "programmability", "restrictions.js"
                )
            ).read(),
        }
    ]

    bundle_with_content = {
        "metadata": {"endpoints": endpoints},
        "modules": modules,
    }

    signed_bundle = sign_payload(
        network.identity(user.local_id), "custom_endpoints", bundle_with_content
    )
    with primary.client() as c:
        r = c.put(
            "/app/custom_endpoints",
            body=signed_bundle,
            headers={"Content-Type": "application/cose"},
        )
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

        LOG.info("'programmability.records' is a read-only table")
        r = c.post("/app/try_read", {"table": "programmability.records"})
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        r = c.post("/app/try_write", {"table": "programmability.records"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code

        LOG.info("'programmability.' is a forbidden namespace")
        r = c.post("/app/try_read", {"table": "programmability.foo"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code
        r = c.post("/app/try_write", {"table": "programmability.foo"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code

        r = c.post("/app/try_read", {"table": "public:programmability.foo"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code
        r = c.post("/app/try_write", {"table": "public:programmability.foo"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code

        LOG.info("Cannot grant access to gov/internal tables")
        r = c.post("/app/try_read", {"table": "public:ccf.gov.foo"})
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        r = c.post("/app/try_write", {"table": "public:ccf.gov.foo"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code

        r = c.post("/app/try_read", {"table": "public:ccf.internal.foo"})
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        r = c.post("/app/try_write", {"table": "public:ccf.internal.foo"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code

        LOG.info("Cannot grant access to (hypothetical) private gov/internal tables")
        r = c.post("/app/try_read", {"table": "ccf.gov.foo"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code
        r = c.post("/app/try_write", {"table": "ccf.gov.foo"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code

        r = c.post("/app/try_read", {"table": "ccf.internal.foo"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code
        r = c.post("/app/try_write", {"table": "ccf.internal.foo"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST.value, r.status_code

    return network


def test_custom_endpoints_js_options(network, args):
    primary, _ = network.find_primary()

    # Make user0 admin, so it can install custom endpoints
    user = network.users[0]
    network.consortium.set_user_data(
        primary, user.service_id, user_data={"isAdmin": True}
    )

    def test_options_patch(c, **kwargs):
        signed_bundle = sign_payload(
            network.identity(user.local_id), "runtime_options", {**kwargs}
        )

        r = c.patch(
            "/app/custom_endpoints/runtime_options",
            body=signed_bundle,
            headers={"Content-Type": "application/cose"},
        )
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        new_options = r.body.json()

        # Check get returns same updated options
        get_r = c.get("/app/custom_endpoints/runtime_options")
        assert get_r.status_code == http.HTTPStatus.OK.value, get_r.status_code
        get_options = get_r.body.json()

        assert new_options == get_options, f"{new_options} != {get_options}"
        return new_options

    with primary.client(None, None) as c:
        r = c.get("/app/custom_endpoints/runtime_options")
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code

        defaults = r.body.json()

        same = test_options_patch(c)
        assert same == defaults

        reduced_heap = test_options_patch(c, max_heap_bytes=42)
        assert reduced_heap == {**defaults, "max_heap_bytes": 42}

        multiple_changes = test_options_patch(
            c, max_execution_time_ms=5000, max_cached_interpreters=15
        )
        assert multiple_changes == {
            **defaults,
            "max_heap_bytes": 42,
            "max_execution_time_ms": 5000,
            "max_cached_interpreters": 15,
        }

        assign_and_reset = test_options_patch(
            c, return_exception_details=True, max_execution_time_ms=None
        )
        assert assign_and_reset == {
            **defaults,
            "max_heap_bytes": 42,
            "max_cached_interpreters": 15,
            "return_exception_details": True,
        }

        reset_all = test_options_patch(
            c,
            max_cached_interpreters=None,
            return_exception_details=None,
            max_heap_bytes=None,
        )
        assert reset_all == defaults

    return network


def test_custom_role_definitions(network, args):
    primary, _ = network.find_primary()
    member = network.consortium.get_any_active_member()

    # Assign a role to user0
    user = network.users[0]
    network.consortium.set_user_data(
        primary,
        user.service_id,
        user_data={"isAdmin": True, "roles": ["ContentGetter"]},
    )

    content_endpoint_def = {
        "get": {
            "js_module": "test.js",
            "js_function": "content",
            "forwarding_required": "never",
            "redirection_strategy": "none",
            "authn_policies": ["user_cert"],
            "mode": "readonly",
            "openapi": {},
        }
    }

    bundle_with_auth = {
        "metadata": {"endpoints": {"/content": content_endpoint_def}},
        "modules": [{"name": "test.js", "module": TESTJS_ROLE}],
    }

    signed_bundle = sign_payload(
        network.identity(user.local_id), "custom_endpoints", bundle_with_auth
    )
    # Install app with auth/role support
    with primary.client() as c:
        r = c.put(
            "/app/custom_endpoints",
            body=signed_bundle,
            headers={"Content-Type": "application/cose"},
        )
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

    # Add role definition
    prop = member.propose(
        primary,
        proposal(
            action(
                "set_role_definition", role="ContentGetter", actions=["/content/read"]
            )
        ),
    )
    member.vote(primary, prop, ballot_yes)

    # user0 has "ContentGetter" role, which has "/content/read" should be able to access "/content"
    with primary.client("user0") as c:
        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body.json()["payload"] == "Test content", r.body.json()

    # But user1 does not
    with primary.client("user1") as c:
        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.FORBIDDEN, r.status_code

    # And unauthenticated users definitely don't
    with primary.client() as c:
        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.UNAUTHORIZED, r.status_code

    # Delete role definition
    prop = member.propose(
        primary,
        proposal(action("set_role_definition", role="ContentGetter", actions=[])),
    )
    member.vote(primary, prop, ballot_yes)

    # Now user0 can't access /content anymore
    with primary.client("user0") as c:
        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.FORBIDDEN, r.status_code

    # Multiple definitions
    prop = member.propose(
        primary,
        proposal(
            action(
                "set_role_definition", role="ContentGetter", actions=["/content/read"]
            ),
            action(
                "set_role_definition",
                role="AllContentGetter",
                actions=["/content/read", "/other_content/read"],
            ),
        ),
    )
    member.vote(primary, prop, ballot_yes)

    bundle_with_auth_both = {
        "metadata": {
            "endpoints": {
                "/content": content_endpoint_def,
                "/other_content": content_endpoint_def,
            }
        },
        "modules": [{"name": "test.js", "module": TESTJS_ROLE}],
    }

    signed_bundle = sign_payload(
        network.identity(user.local_id), "custom_endpoints", bundle_with_auth_both
    )
    # Install two endpoints with role auth
    with primary.client() as c:
        r = c.put(
            "/app/custom_endpoints",
            body=signed_bundle,
            headers={"Content-Type": "application/cose"},
        )
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

    # Assign the new role to user0
    user = network.users[0]
    network.consortium.set_user_data(
        primary,
        user.service_id,
        user_data={"isAdmin": True, "roles": ["ContentGetter", "AllContentGetter"]},
    )

    # user0 has access both now
    with primary.client("user0") as c:
        r = c.get("/app/content")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body.json()["payload"] == "Test content", r.body.json()
        r = c.get("/app/other_content")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body.json()["payload"] == "Test content", r.body.json()

    return network


def deploy_npm_app_custom(network, args):
    primary, _ = network.find_nodes()
    user = network.users[0]

    app_dir = os.path.join(npm_tests.THIS_DIR, "npm-app")

    LOG.info("Deploying npm app")
    bundle_path = os.path.join(
        app_dir, "dist", "bundle.json"
    )  # Produced by build_npm_app

    signed_bundle = sign_payload(
        network.identity(user.local_id),
        "custom_endpoints",
        json.load(open(bundle_path)),
    )
    with primary.client() as c:
        r = c.put(
            "/app/custom_endpoints",
            body=signed_bundle,
            headers={"Content-Type": "application/cose"},
        )
        assert r.status_code == http.HTTPStatus.NO_CONTENT.value, r.status_code

    return network


def run(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
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
        network = test_custom_endpoints_circular_includes(network, args)
        network = test_custom_endpoints_kv_restrictions(network, args)
        network = test_custom_role_definitions(network, args)
        network = test_custom_endpoints_js_options(network, args)

        network = npm_tests.build_npm_app(network, args)
        network = deploy_npm_app_custom(network, args)
        network = npm_tests.test_npm_app(network, args)


if __name__ == "__main__":
    cr = ConcurrentRunner()

    cr.add(
        "programmability",
        run,
        package="samples/apps/programmability/programmability",
        js_app_bundle=None,
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),
        initial_user_count=2,
        initial_member_count=1,
    )

    cr.add(
        "auto",
        jwt_test.run_auto,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=1),
        jwt_key_refresh_interval_s=1,
        issuer_port=12345,
    )

    cr.add(
        "manual",
        jwt_test.run_manual,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=1),
        jwt_key_refresh_interval_s=100000,
        issuer_port=12346,
    )

    cr.add(
        "ca_cert",
        jwt_test.run_ca_cert,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
    )

    cr.run()
