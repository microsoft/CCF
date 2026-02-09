# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import http
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs
from infra.runner import ConcurrentRunner
import os
import tempfile
import base64
import json
import time
from infra.jwt_issuer import JwtAlg, JwtAuthType, JwtIssuer, make_bearer_header
import datetime
import re
import uuid
from http import HTTPStatus
import subprocess
from contextlib import contextmanager
from functools import partial

from loguru import logger as LOG

utctime = partial(datetime.datetime, tzinfo=datetime.UTC)


@reqs.description("Test custom authorization")
def test_custom_auth(network, args):
    primary, _ = network.find_nodes()

    with primary.client("user0") as c:
        r = c.get("/app/custom_auth", headers={"Authorization": "Bearer 42"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body.json()

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        network = test_custom_auth(network, args)


# Context manager to temporarily set JS execution limits.
# NB: Limits are currently applied to governance runtimes as well, so limits
# must be high enough that a proposal to restore the defaults can pass.
@contextmanager
def temporary_js_limits(network, primary, **kwargs):
    with primary.client() as c:
        # fetch defaults from js_metrics endpoint
        r = c.get("/node/js_metrics")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        body = r.body.json()
        default_max_heap_size = body["max_heap_size"]
        default_max_stack_size = body["max_stack_size"]
        default_max_execution_time = body["max_execution_time"]

    default_kwargs = {
        "max_heap_bytes": default_max_heap_size,
        "max_stack_bytes": default_max_stack_size,
        "max_execution_time_ms": default_max_execution_time,
        "return_exception_details": True,
    }

    temp_kwargs = default_kwargs.copy()
    temp_kwargs.update(**kwargs)
    LOG.info(f"Setting JS runtime options: {temp_kwargs}")
    network.consortium.set_js_runtime_options(
        primary,
        **temp_kwargs,
    )

    yield

    # Restore defaults
    network.consortium.set_js_runtime_options(primary, **default_kwargs)


def set_issuer_with_a_key(primary, network, issuer, kid, constraint):
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        jwt_cert_der = infra.crypto.cert_pem_to_der(issuer.cert_pem)
        der_b64 = base64.b64encode(jwt_cert_der).decode("ascii")
        data = {
            "issuer": issuer.issuer_url,
            "auto_refresh": False,
            "jwks": {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": kid,
                        "x5c": [der_b64],
                        "issuer": constraint,
                    }
                ]
            },
        }
        json.dump(data, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)


def parse_error_message(r):
    return r.body.json()["error"]["details"][0]["message"]


def try_auth(primary, issuer, kid, iss, tid):
    with primary.client("user0") as c:
        LOG.info(f"Creating JWT with kid={kid} iss={iss} tenant={tid}")
        return c.get(
            "/app/jwt",
            headers=make_bearer_header(
                issuer.issue_jwt(kid, claims={"iss": iss, "tid": tid})
            ),
        )


@reqs.description("Test stack size limit")
def test_stack_size_limit(network, args):
    primary, _ = network.find_nodes()

    safe_depth = 1
    depth = safe_depth
    max_depth = 8192

    with primary.client("user0") as c:
        r = c.post("/app/recursive", body={"depth": safe_depth})
        assert r.status_code == http.HTTPStatus.OK, r.status_code

        max_stack_bytes = (
            512 * 1024
        )  # Lower than 1024 * 1024 default, but enough to pass a proposal to restore the limit
        with temporary_js_limits(network, primary, max_stack_bytes=max_stack_bytes):
            while depth <= max_depth:
                depth *= 2
                r = c.post("/app/recursive", body={"depth": depth})
                if r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR:
                    message = parse_error_message(r)
                    assert message == "InternalError: stack overflow", message
                    LOG.info(
                        f"Stack overflow at depth={depth} with max_stack_bytes={max_stack_bytes}"
                    )
                    break

            assert depth < max_depth, f"No stack overflow trigger at max depth {depth}"

        r = c.post("/app/recursive", body={"depth": safe_depth})
        assert r.status_code == http.HTTPStatus.OK, r

        # Lower the cap until we likely run out of stack out of user code,
        # and check that we don't crash. Check we return an error message
        cap = max_stack_bytes
        while cap > 0:
            cap //= 2
            LOG.info(f"Max stack size: {cap}")
            with temporary_js_limits(network, primary, max_stack_bytes=cap):
                r = c.post("/app/recursive", body={"depth": 1})
                if r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR:
                    message = r.body.json()["error"]["message"]
                    assert message == "Exception thrown while executing.", message
                    break

        # Cap is so low that we must run out before we enter user code
        with temporary_js_limits(network, primary, max_stack_bytes=100):
            r = c.post("/app/recursive", body={"depth": 1})
            assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR
            message = r.body.json()["error"]["message"]
            assert message == "Exception thrown while executing.", message

    return network


@reqs.description("Test heap size limit")
def test_heap_size_limit(network, args):
    primary, _ = network.find_nodes()

    safe_size = 5 * 1024 * 1024
    unsafe_size = 500 * 1024 * 1024

    with primary.client("user0") as c:
        r = c.post("/app/alloc", body={"size": safe_size})
        assert r.status_code == http.HTTPStatus.OK, r

        with temporary_js_limits(network, primary, max_heap_bytes=3 * 1024 * 1024):
            r = c.post("/app/alloc", body={"size": safe_size})
            assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r
            message = parse_error_message(r)
            assert message == "InternalError: out of memory", message

        r = c.post("/app/alloc", body={"size": safe_size})
        assert r.status_code == http.HTTPStatus.OK, r

        r = c.post("/app/alloc", body={"size": unsafe_size})
        message = parse_error_message(r)
        assert message == "InternalError: out of memory", message

        # Lower the cap until we likely run out of heap out of user code,
        # and check that we don't crash and return an error message
        cap = safe_size
        while cap > 0:
            cap //= 2
            LOG.info(f"Heap max size: {cap}")
            with temporary_js_limits(network, primary, max_heap_bytes=cap):
                r = c.post("/app/alloc", body={"size": 1})
                if r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR:
                    message = r.body.json()["error"]["message"]
                    assert message == "Exception thrown while executing.", message
                    break

        # Cap is so low that we must run out before we enter user code
        with temporary_js_limits(network, primary, max_heap_bytes=100):
            r = c.post("/app/alloc", body={"size": 1})
            assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR
            message = r.body.json()["error"]["message"]
            assert message == "Exception thrown while executing.", message

    return network


@reqs.description("Test execution time limit")
def test_execution_time_limit(network, args):
    primary, _ = network.find_nodes()

    safe_time = 50
    unsafe_time = 10000

    with primary.client("user0") as c:
        r = c.post("/app/sleep", body={"time": safe_time})
        assert r.status_code == http.HTTPStatus.OK, r

        with temporary_js_limits(network, primary, max_execution_time_ms=30):
            r = c.post("/app/sleep", body={"time": safe_time})
            assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r
            message = parse_error_message(r)
            assert message == "InternalError: interrupted", message

        r = c.post("/app/sleep", body={"time": safe_time})
        assert r.status_code == http.HTTPStatus.OK, r

        r = c.post("/app/sleep", body={"time": unsafe_time})
        assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR, r
        message = parse_error_message(r)
        assert message == "InternalError: interrupted", message

        # Lower the cap until we likely run out of heap out of user code,
        # and check that we don't crash and return an error message
        cap = safe_time
        while cap > 0:
            cap //= 2
            LOG.info(f"Max exec time: {cap}")
            with temporary_js_limits(network, primary, max_execution_time_ms=cap):
                r = c.post("/app/sleep", body={"time": 10})
                if r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR:
                    message = r.body.json()["error"]["message"]
                    assert message == "Operation took too long to complete.", message
                    break

        # Cap is so low that we must run out before we enter user code
        with temporary_js_limits(network, primary, max_execution_time_ms=0):
            r = c.post("/app/sleep", body={"time": 10})
            assert r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR
            message = r.body.json()["error"]["message"]
            assert message == "Operation took too long to complete.", message

    return network


def run_limits(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        network = test_stack_size_limit(network, args)
        network = test_heap_size_limit(network, args)
        network = test_execution_time_limit(network, args)


@reqs.description("Cert authentication")
def test_cert_auth(network, args):
    def create_keypair(local_id, valid_from, validity_days):
        privk_pem, _ = infra.crypto.generate_ec_keypair()
        with open(
            os.path.join(network.common_dir, f"{local_id}_privk.pem"),
            "w",
            encoding="ascii",
        ) as f:
            f.write(privk_pem)

        cert = infra.crypto.generate_cert(
            privk_pem,
            valid_from=valid_from,
            validity_days=validity_days,
        )
        with open(
            os.path.join(network.common_dir, f"{local_id}_cert.pem"),
            "w",
            encoding="ascii",
        ) as f:
            f.write(cert)

    primary, _ = network.find_primary()

    LOG.info("User with old cert cannot call user-authenticated endpoint")
    local_user_id = "in_the_past"
    create_keypair(
        local_user_id,
        datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=50),
        3,
    )
    network.consortium.add_user(primary, local_user_id)

    with primary.client(local_user_id) as c:
        r = c.get("/app/cert")
        assert r.status_code == HTTPStatus.UNAUTHORIZED, r
        assert "Not After" in parse_error_message(r), r

    LOG.info("User with future cert cannot call user-authenticated endpoint")
    local_user_id = "in_the_future"
    create_keypair(
        local_user_id,
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=50),
        3,
    )
    network.consortium.add_user(primary, local_user_id)

    with primary.client(local_user_id) as c:
        r = c.get("/app/cert")
        assert r.status_code == HTTPStatus.UNAUTHORIZED, r
        assert "Not Before" in parse_error_message(r), r

    LOG.info("No leeway added to cert time evaluation")
    local_user_id = "just_expired"
    valid_from = datetime.datetime.now(datetime.UTC) - datetime.timedelta(
        days=1, seconds=2
    )
    create_keypair(local_user_id, valid_from, 1)
    network.consortium.add_user(primary, local_user_id)

    with primary.client(local_user_id) as c:
        r = c.get("/app/cert")
        assert r.status_code == HTTPStatus.UNAUTHORIZED, r
        assert "Not After" in parse_error_message(r), r

    LOG.info("Long-lived cert doesn't wraparound")
    local_user_id = "long_lived"
    valid_from = datetime.datetime.now(datetime.UTC)
    create_keypair(local_user_id, valid_from, 1_000_000)
    network.consortium.add_user(primary, local_user_id)

    with primary.client(local_user_id) as c:
        r = c.get("/app/cert")
        assert r.status_code == HTTPStatus.OK, r

    LOG.info("Future Not-Before doesn't wraparound")
    local_user_id = "distant_future"
    # system_clock max representable time is currently 2262-04-11, so use a date after that to check for wraparound
    valid_from = utctime(
        year=2262, month=4, day=12
    )
    create_keypair(local_user_id, valid_from, 4)
    network.consortium.add_user(primary, local_user_id)

    with primary.client(local_user_id) as c:
        r = c.get("/app/cert")
        assert r.status_code == HTTPStatus.UNAUTHORIZED, r
        expected = (
            f"certificate's Not Before validity period {int(valid_from.timestamp())}"
        )
        actual = parse_error_message(r)
        assert expected in actual, r

    LOG.info("Representable range")
    local_user_id = "representable"
    # Python crypto enforces minimum Not-Before of 1950-01-01
    valid_from = utctime(
        year=1950, month=1, day=1
    )
    # Probe maximum validity range
    validity_days = (utctime(year=9999, month=12, day=31) - valid_from).days
    create_keypair(local_user_id, valid_from, validity_days)
    network.consortium.add_user(primary, local_user_id)

    with primary.client(local_user_id) as c:
        r = c.get("/app/cert")
        assert r.status_code == HTTPStatus.OK, r

    return network


@reqs.description("JWT authentication as by OpenID spec")
def test_jwt_auth(network, args):
    primary, _ = network.find_nodes()

    issuer = JwtIssuer("https://example.issuer")

    jwt_kid = "my_key_id"

    LOG.info("Add JWT issuer with initial keys")

    set_issuer_with_a_key(primary, network, issuer, jwt_kid, issuer.name)

    LOG.info("Calling jwt endpoint after storing keys")
    with primary.client("user0") as c:
        r = c.get("/app/jwt", headers=make_bearer_header("garbage"))
        assert r.status_code == HTTPStatus.UNAUTHORIZED, r.status_code
        assert "Malformed JWT" in parse_error_message(r), r

        jwt_mismatching_key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
        jwt = infra.crypto.create_jwt({}, jwt_mismatching_key_priv_pem, jwt_kid)
        r = c.get("/app/jwt", headers=make_bearer_header(jwt))
        assert r.status_code == HTTPStatus.UNAUTHORIZED, r.status_code
        assert "JWT payload is missing required field" in parse_error_message(r), r

        r = c.get(
            "/app/jwt",
            headers=make_bearer_header(issuer.issue_jwt(jwt_kid)),
        )
        assert r.status_code == HTTPStatus.OK, r.status_code

        LOG.info("Calling JWT with too-late nbf")
        r = c.get(
            "/app/jwt",
            headers=make_bearer_header(
                issuer.issue_jwt(jwt_kid, claims={"nbf": time.time() + 60})
            ),
        )
        assert r.status_code == HTTPStatus.UNAUTHORIZED, r.status_code
        assert "is before token's Not Before" in parse_error_message(r), r

        LOG.info("Calling JWT with too-early exp")
        r = c.get(
            "/app/jwt",
            headers=make_bearer_header(
                issuer.issue_jwt(jwt_kid, claims={"exp": time.time() - 60})
            ),
        )
        assert r.status_code == HTTPStatus.UNAUTHORIZED, r.status_code
        assert "is after token's Expiration Time" in parse_error_message(r), r

    network.consortium.remove_jwt_issuer(primary, issuer.name)
    return network


@reqs.description("JWT authentication as by OpenID spec with raw public key")
def test_jwt_auth_raw_key(network, args):
    primary, _ = network.find_nodes()

    for alg in [JwtAlg.RS256, JwtAlg.ES256]:
        issuer = JwtIssuer("noautorefresh://issuer", alg=alg, auth_type=JwtAuthType.KEY)
        jwt_kid = "my_key_id"
        issuer.register(network, kid=jwt_kid)

        LOG.info("Calling jwt endpoint after storing keys")
        with primary.client("user0") as c:
            token = issuer.issue_jwt(jwt_kid)
            r = c.get(
                "/app/jwt",
                headers=make_bearer_header(token),
            )
            assert r.status_code == HTTPStatus.OK, r.status_code

            # Change client's key only, new token shouldn't pass validation.
            issuer.refresh_keys(kid=jwt_kid, send_update=False)
            token = issuer.issue_jwt(jwt_kid)
            r = c.get(
                "/app/jwt",
                headers=make_bearer_header(token),
            )
            assert r.status_code == HTTPStatus.UNAUTHORIZED, r.status_code

    network.consortium.remove_jwt_issuer(primary, issuer.name)
    return network


@reqs.description("JWT authentication as by MSFT Entra (single tenant)")
def test_jwt_auth_msft_single_tenant(network, args):
    """For a specific tenant, only tokens with this issuer+tenant can auth."""

    primary, _ = network.find_nodes()

    TENANT_ID = "9188050d-6c67-4c5b-b112-36a304b66da"
    ISSUER_TENANT = (
        "https://login.microsoftonline.com/9188050d-6c67-4c5b-b112-36a304b66da/v2.0"
    )

    issuer = JwtIssuer(name="https://login.microsoftonline.com")
    jwt_kid = "my_key_id"

    set_issuer_with_a_key(primary, network, issuer, jwt_kid, ISSUER_TENANT)

    r = try_auth(primary, issuer, jwt_kid, ISSUER_TENANT, "garbage_tenant")
    assert r.status_code == HTTPStatus.UNAUTHORIZED, r
    assert "failed issuer constraint validation" in parse_error_message(r), r

    r = try_auth(primary, issuer, jwt_kid, ISSUER_TENANT, "{tenantid}")
    assert r.status_code == HTTPStatus.UNAUTHORIZED, r
    assert "failed issuer constraint validation" in parse_error_message(r), r

    r = try_auth(primary, issuer, jwt_kid, ISSUER_TENANT, TENANT_ID)
    assert r.status_code == HTTPStatus.OK, r

    network.consortium.remove_jwt_issuer(primary, issuer.name)

    r = try_auth(primary, issuer, jwt_kid, ISSUER_TENANT, TENANT_ID)
    assert r.status_code == HTTPStatus.UNAUTHORIZED, r
    assert f"key not found for kid {jwt_kid}" in parse_error_message(r), r

    return network


@reqs.description("JWT authentication as by MSFT Entra (multiple tenants)")
def test_jwt_auth_msft_multitenancy(network, args):
    """For a common tenant, all tokens from this issuer can auth,
    no matter which tenant is specified."""

    primary, _ = network.find_nodes()

    COMMNON_ISSUER = "https://login.microsoftonline.com/{tenantid}/v2.0"
    TENANT_ID = "9188050d-6c67-4c5b-b112-36a304b66da"
    ISSUER_TENANT = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
    ANOTHER_TENANT_ID = "deadbeef-6c67-4c5b-b112-36a304b66da"
    ISSUER_ANOTHER = f"https://login.microsoftonline.com/{ANOTHER_TENANT_ID}/v2.0"

    issuer = JwtIssuer(name="https://login.microsoftonline.com")

    jwt_kid_1 = "my_key_id_1"
    jwt_kid_2 = "my_key_id_2"

    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        jwt_cert_der = infra.crypto.cert_pem_to_der(issuer.cert_pem)
        der_b64 = base64.b64encode(jwt_cert_der).decode("ascii")
        data = {
            "issuer": issuer.issuer_url,
            "auto_refresh": False,
            "jwks": {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": jwt_kid_1,
                        "x5c": [der_b64],
                        "issuer": COMMNON_ISSUER,
                    },
                    {
                        "kty": "RSA",
                        "kid": jwt_kid_2,
                        "x5c": [der_b64],
                        "issuer": ISSUER_TENANT,
                    },
                ]
            },
        }
        json.dump(data, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    r = try_auth(primary, issuer, jwt_kid_1, ISSUER_TENANT, TENANT_ID)
    assert r.status_code == HTTPStatus.OK, r

    r = try_auth(primary, issuer, jwt_kid_1, ISSUER_ANOTHER, ANOTHER_TENANT_ID)
    assert r.status_code == HTTPStatus.OK, r

    r = try_auth(primary, issuer, jwt_kid_1, ISSUER_TENANT, ANOTHER_TENANT_ID)
    assert r.status_code == HTTPStatus.UNAUTHORIZED, r
    assert "failed issuer constraint validation" in parse_error_message(r), r

    r = try_auth(primary, issuer, jwt_kid_2, ISSUER_TENANT, TENANT_ID)
    assert r.status_code == HTTPStatus.OK, r

    r = try_auth(primary, issuer, jwt_kid_2, ISSUER_ANOTHER, ANOTHER_TENANT_ID)
    assert r.status_code == HTTPStatus.UNAUTHORIZED, r
    assert "failed issuer constraint validation" in parse_error_message(r), r

    network.consortium.remove_jwt_issuer(primary, issuer.name)

    r = try_auth(primary, issuer, jwt_kid_1, ISSUER_TENANT, TENANT_ID)
    assert r.status_code == HTTPStatus.UNAUTHORIZED, r
    assert f"key not found for kid {jwt_kid_1}" in parse_error_message(r), r

    r = try_auth(primary, issuer, jwt_kid_2, ISSUER_TENANT, TENANT_ID)
    assert r.status_code == HTTPStatus.UNAUTHORIZED, r
    assert f"key not found for kid {jwt_kid_2}" in parse_error_message(r), r

    return network


@reqs.description("JWT authentication with same kids for different issuers")
def test_jwt_auth_msft_same_kids_different_issuers(network, args):
    """Multiple issuer can share same kid with their own constraints specified.
    So when issuer1 adds it with constraint1, and issuer2 added it with constraint2,
    then tokens from both issuer1 and issuer2 can go.
    However, when issuer1 is removed, issuer2 has to remain capable of
    authenticating with their tokens."""

    primary, _ = network.find_nodes()

    TENANT_ID = "9188050d-6c67-4c5b-b112-36a304b66da"
    ISSUER_TENANT = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
    ANOTHER_TENANT_ID = "deadbeef-6c67-4c5b-b112-36a304b66da"
    ISSUER_ANOTHER = f"https://login.microsoftonline.com/{ANOTHER_TENANT_ID}/v2.0"

    issuer = JwtIssuer(name=ISSUER_TENANT)
    another = JwtIssuer(name=ISSUER_ANOTHER)

    # Immitate same key sharing
    another.cert_pem, another.key_priv_pem = issuer.cert_pem, issuer.key_priv_pem

    jwt_kid = "my_key_id"

    set_issuer_with_a_key(primary, network, issuer, jwt_kid, ISSUER_TENANT)

    r = try_auth(primary, issuer, jwt_kid, ISSUER_TENANT, TENANT_ID)
    assert r.status_code == HTTPStatus.OK, r

    r = try_auth(primary, another, jwt_kid, ISSUER_ANOTHER, ANOTHER_TENANT_ID)
    assert r.status_code == HTTPStatus.UNAUTHORIZED, r
    assert "failed issuer constraint validation" in parse_error_message(r), r

    set_issuer_with_a_key(primary, network, another, jwt_kid, ISSUER_ANOTHER)

    r = try_auth(primary, issuer, jwt_kid, ISSUER_TENANT, TENANT_ID)
    assert r.status_code == HTTPStatus.OK, r

    r = try_auth(primary, another, jwt_kid, ISSUER_ANOTHER, ANOTHER_TENANT_ID)
    assert r.status_code == HTTPStatus.OK, r

    network.consortium.remove_jwt_issuer(primary, issuer.name)

    r = try_auth(primary, issuer, jwt_kid, ISSUER_TENANT, TENANT_ID)
    assert r.status_code == HTTPStatus.UNAUTHORIZED, r
    assert "failed issuer constraint validation" in parse_error_message(r), r

    r = try_auth(primary, another, jwt_kid, ISSUER_ANOTHER, ANOTHER_TENANT_ID)
    assert r.status_code == HTTPStatus.OK, r

    network.consortium.remove_jwt_issuer(primary, another.name)

    r = try_auth(primary, issuer, jwt_kid, ISSUER_TENANT, TENANT_ID)
    assert r.status_code == HTTPStatus.UNAUTHORIZED, r
    assert f"key not found for kid {jwt_kid}" in parse_error_message(r), r

    r = try_auth(primary, another, jwt_kid, ISSUER_ANOTHER, ANOTHER_TENANT_ID)
    assert r.status_code == HTTPStatus.UNAUTHORIZED, r
    assert f"key not found for kid {jwt_kid}" in parse_error_message(r), r

    return network


@reqs.description("JWT authentication with same kid with constraint overwrite")
def test_jwt_auth_msft_same_kids_overwrite_constraint(network, args):
    """If issuer sets the same kid with different constraint we have to
    overwrite it. Test exists because this was found as a bug during feature
    development and was very easy to miss updating the constraint for
    existing kids."""

    primary, _ = network.find_nodes()

    COMMNON_ISSUER = "https://login.microsoftonline.com/{tenantid}/v2.0"
    TENANT_ID = "9188050d-6c67-4c5b-b112-36a304b66da"
    ISSUER_TENANT = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
    ANOTHER_TENANT_ID = "deadbeef-6c67-4c5b-b112-36a304b66da"
    ISSUER_ANOTHER = f"https://login.microsoftonline.com/{ANOTHER_TENANT_ID}/v2.0"

    issuer = JwtIssuer(name=ISSUER_TENANT)
    jwt_kid = "my_key_id"

    set_issuer_with_a_key(primary, network, issuer, jwt_kid, COMMNON_ISSUER)

    r = try_auth(primary, issuer, jwt_kid, ISSUER_TENANT, TENANT_ID)
    assert r.status_code == HTTPStatus.OK, r

    r = try_auth(primary, issuer, jwt_kid, ISSUER_ANOTHER, ANOTHER_TENANT_ID)
    assert r.status_code == HTTPStatus.OK, r

    set_issuer_with_a_key(primary, network, issuer, jwt_kid, ISSUER_TENANT)

    r = try_auth(primary, issuer, jwt_kid, ISSUER_TENANT, TENANT_ID)
    assert r.status_code == HTTPStatus.OK, r

    r = try_auth(primary, issuer, jwt_kid, ISSUER_ANOTHER, ANOTHER_TENANT_ID)
    assert r.status_code == HTTPStatus.UNAUTHORIZED, r
    assert "failed issuer constraint validation" in parse_error_message(r), r

    network.consortium.remove_jwt_issuer(primary, issuer.name)

    r = try_auth(primary, issuer, jwt_kid, ISSUER_TENANT, TENANT_ID)
    assert r.status_code == HTTPStatus.UNAUTHORIZED, r
    assert f"key not found for kid {jwt_kid}" in parse_error_message(r), r

    r = try_auth(primary, issuer, jwt_kid, ISSUER_ANOTHER, ANOTHER_TENANT_ID)
    assert r.status_code == HTTPStatus.UNAUTHORIZED, r
    assert f"key not found for kid {jwt_kid}" in parse_error_message(r), r

    return network


@reqs.description("Role-based access")
def test_role_based_access(network, args):
    primary, _ = network.find_nodes()

    users = network.users
    assert len(users) >= 3

    # Confirm that initially, no user can read or write from the secret, or modify roles
    for user in users:
        with primary.client(user.local_id) as c:
            r = c.get("/app/secret")
            assert r.status_code == 401, r.status_code

            r = c.post("/app/secret", {"new_secret": "I'm in charge"})
            assert r.status_code == 401, r.status_code

            r = c.post(
                "/app/roles",
                {"target_id": user.service_id, "target_role": "secret_reader"},
            )
            assert r.status_code == 401, r.status_code

    # Bootstrap with a member-governance operation to give first user special role, allowing them to set other users' roles
    network.consortium.set_user_data(
        primary, users[0].service_id, {"role": "role_master"}
    )

    readers = []
    writers = []

    # First user can now assign roles of itself and others
    with primary.client(users[0].local_id) as c:
        r = c.post(
            "/app/roles",
            {"target_id": users[0].service_id, "target_role": "secret_reader"},
        )
        assert r.status_code == 204, r.status_code
        readers.append(users[0])

        r = c.post(
            "/app/roles",
            {"target_id": users[1].service_id, "target_role": "role_master"},
        )
        assert r.status_code == 204, r.status_code

    # Second user can now assign roles, thanks to assignment from first user
    with primary.client(users[1].local_id) as c:
        r = c.post(
            "/app/roles",
            {"target_id": users[2].service_id, "target_role": "secret_reader"},
        )
        assert r.status_code == 204, r.status_code
        readers.append(users[2])

        r = c.post(
            "/app/roles",
            {"target_id": users[2].service_id, "target_role": "secret_writer"},
        )
        assert r.status_code == 204, r.status_code
        writers.append(users[2])

        r = c.post(
            "/app/roles",
            {"target_id": users[3].service_id, "target_role": "secret_reader"},
        )
        assert r.status_code == 204, r.status_code
        readers.append(users[3])

    # Those role assignments allow some users to read and write
    for user in users:
        with primary.client(user.local_id) as c:
            r = c.post(
                "/app/secret", {"new_secret": f"My favourite person is {user.local_id}"}
            )
            if user in writers:
                assert r.status_code == 204, r.status_code
            else:
                assert r.status_code == 401, r.status_code

            r = c.get("/app/secret")
            if user in readers:
                assert r.status_code == 200, r.status_code
            else:
                assert r.status_code == 401, r.status_code


def run_authn(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        network = test_cert_auth(network, args)
        network = test_jwt_auth(network, args)
        network = test_jwt_auth_raw_key(network, args)
        network = test_jwt_auth_msft_single_tenant(network, args)
        network = test_jwt_auth_msft_multitenancy(network, args)
        network = test_jwt_auth_msft_same_kids_different_issuers(network, args)
        network = test_jwt_auth_msft_same_kids_overwrite_constraint(network, args)
        network = test_role_based_access(network, args)


@reqs.description("Test content types")
def test_content_types(network, args):
    primary, _ = network.find_nodes()

    with primary.client("user0") as c:
        r = c.post("/app/text", body="text")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "text/plain"
        assert r.body.text() == "text"

        r = c.post("/app/json", body={"foo": "bar"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "application/json"
        assert r.body.json() == {"foo": "bar"}

        r = c.post("/app/binary", body=b"\x00" * 42)
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "application/octet-stream"
        assert r.body.data() == b"\x00" * 42, r.body

        r = c.post("/app/custom", body="text", headers={"content-type": "foo/bar"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "text/plain"
        assert r.body.text() == "text"

    return network


@reqs.description("Test accept header")
def test_accept_header(network, args):
    primary, _ = network.find_nodes()

    with primary.client() as c:
        r = c.get("/node/commit", headers={"accept": "nonsense"})
        assert r.status_code == http.HTTPStatus.BAD_REQUEST.value

        r = c.get("/node/commit", headers={"accept": "text/html"})
        assert r.status_code == http.HTTPStatus.NOT_ACCEPTABLE.value

        r = c.get(
            "/node/commit",
            headers={"accept": "text/html;q=0.9,image/jpeg;video/mpeg;q=0.8"},
        )
        assert r.status_code == http.HTTPStatus.NOT_ACCEPTABLE.value

        r = c.get("/node/commit", headers={"accept": "*/*"})
        assert r.status_code == http.HTTPStatus.OK.value

        r = c.get("/node/commit", headers={"accept": "application/*"})
        assert r.status_code == http.HTTPStatus.OK.value

        r = c.get("/node/commit", headers={"accept": "application/json"})
        assert r.status_code == http.HTTPStatus.OK.value
        assert r.headers["content-type"] == "application/json"

        r = c.get(
            "/node/commit",
            headers={"accept": "text/html;q=0.9,image/jpeg;video/mpeg;q=0.8,*/*;q=0.1"},
        )
        assert r.status_code == http.HTTPStatus.OK.value

        r = c.get(
            "/node/commit",
            headers={
                "accept": "text/html;q=0.9,image/jpeg;video/mpeg;q=0.8,application/json;q=0.1"
            },
        )
        assert r.status_code == http.HTTPStatus.OK.value
        assert r.headers["content-type"] == "application/json"

    return network


@reqs.description("Test supported methods")
def test_supported_methods(network, args):
    primary, _ = network.find_nodes()

    with primary.client("user0") as c:
        # Test ALLOW header when wrong method is used
        r = c.delete("/app/text")
        assert r.status_code == http.HTTPStatus.METHOD_NOT_ALLOWED
        allow = r.headers.get("allow")
        assert allow is not None
        assert "OPTIONS" in allow
        assert "POST" in allow

        # Test ALLOW header when OPTIONS method is used on POST-only app endpoint
        r = c.options("/app/text")
        assert r.status_code == http.HTTPStatus.NO_CONTENT
        allow = r.headers.get("allow")
        assert allow is not None
        assert "OPTIONS" in allow
        assert "POST" in allow

        # Test ALLOW header when OPTIONS method is used on GET-only framework endpoint
        r = c.options("/node/commit")
        assert r.status_code == http.HTTPStatus.NO_CONTENT
        allow = r.headers.get("allow")
        assert allow is not None
        assert "OPTIONS" in allow
        assert "GET" in allow

    return network


@reqs.description("Test unknown path")
def test_unknown_path(network, args):
    primary, _ = network.find_nodes()

    with primary.client("user0") as c:
        r = c.get("/app/not/a/real/path")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code
        r = c.post("/app/not/a/real/path")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code
        r = c.delete("/app/not/a/real/path")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code

        r = c.post("/app/unknown")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code

    with primary.client() as c:
        r = c.get("/app/not/a/real/path")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code
        r = c.post("/app/not/a/real/path")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code
        r = c.delete("/app/not/a/real/path")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code

        r = c.post("/app/unknown")
        assert r.status_code == http.HTTPStatus.NOT_FOUND, r.status_code

    return network


def run_content_types(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        network = test_content_types(network, args)
        network = test_accept_header(network, args)
        network = test_supported_methods(network, args)
        network = test_unknown_path(network, args)


@reqs.description("Test request object API")
def test_random_api(args):
    # Test that Math.random() does not repeat values:
    # - on multiple invocations within a single request
    # - on multiple requests
    # - on network restarts

    seen_values = set()

    def assert_fresh(n):
        assert n not in seen_values, f"{n} has already been returned"
        seen_values.add(n)

    n_repeats = 3
    for _ in range(n_repeats):
        with infra.network.network(
            args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
        ) as network:
            network.start_and_open(args)
            primary, _ = network.find_nodes()
            for _ in range(n_repeats):
                with primary.client() as c:
                    r = c.get("/app/make_randoms")
                    assert r.status_code == 200, r
                    for _, n in r.body.json().items():
                        assert_fresh(n)


@reqs.description("Test request object API")
def test_request_object_api(network, args):
    primary, _ = network.find_nodes()

    def test_expectations(expected_fields, response):
        assert response.status_code == http.HTTPStatus.OK, response
        j = response.body.json()
        for k, v in expected_fields.items():
            ks = k.split(".")
            current = j
            for k_ in ks:
                assert k_ in current, f"Missing field {k} from response body"
                current = current[k_]
            actual = current
            assert (
                v == actual
            ), f"Mismatch at field {k}. Expected '{v}', response contains '{actual}'"
            # LOG.success(f"{k} == {v}")

    def test_url(expected_fields, client, base_url, query="", url_params=None):
        url = base_url
        expected_fields["route"] = base_url

        if url_params is not None:
            url = url.format(**url_params)

        expected_fields["path"] = url

        if len(query) > 0:
            url += f"?{query}"

        expected_fields["query"] = query
        expected_fields["url"] = url

        expected_fields["method"] = "GET"
        test_expectations(expected_fields, client.get(url))
        expected_fields["method"] = "POST"
        test_expectations(expected_fields, client.post(url))
        expected_fields["method"] = "DELETE"
        test_expectations(expected_fields, client.delete(url))

    def test_client(expected_fields, client):
        test_url(
            {**expected_fields, "hostname": f"{client.hostname}"},
            client,
            "/app/echo",
        )
        test_url(
            {**expected_fields, "hostname": f"{client.hostname}"},
            client,
            "/app/echo",
            query="a=42&b=hello_world",
        )
        test_url(
            {**expected_fields, "hostname": f"{client.hostname}"},
            client,
            "/app/echo/{foo}",
            url_params={"foo": "bar"},
        )
        test_url(
            {**expected_fields, "hostname": f"{client.hostname}"},
            client,
            "/app/echo/{foo}",
            query="a=42&b=hello_world",
            url_params={"foo": "bar"},
        )

    user = network.users[0]
    with primary.client(user.local_id) as c:
        test_client({"caller.policy": "user_cert", "caller.id": user.service_id}, c)

    with primary.client() as c:
        test_client({"caller.policy": "no_auth"}, c)

    return network


@reqs.description("Test Date API")
def test_datetime_api(network, args):
    primary, _ = network.find_nodes()

    with primary.client() as c:
        r = c.get("/time_now")
        local_time = datetime.datetime.now(datetime.timezone.utc)
        assert r.status_code == http.HTTPStatus.OK, r
        body = r.body.json()

        # Python datetime "ISO" doesn't parse Z suffix, so replace it
        definitely_now = body["definitely_now"].replace("Z", "+00:00")
        definitely_1970 = body["definitely_1970"].replace("Z", "+00:00")

        # Assume less than 5ms of execution time between grabbing timestamps, and confirm that untrustedDateTime has no effect
        service_time = datetime.datetime.fromisoformat(definitely_now)
        untrusted_on = datetime.datetime.fromisoformat(
            body["untrusted_on"].replace("Z", "+00:00")
        )
        untrusted_off = datetime.datetime.fromisoformat(
            body["untrusted_off"].replace("Z", "+00:00")
        )
        diff = (untrusted_on - service_time).total_seconds()
        assert diff < 0.005, diff
        diff = (untrusted_off - untrusted_on).total_seconds()
        assert diff < 0.005, diff

        # Assume less than 1 second of clock skew + execution time, and that service time is now
        diff = (local_time - service_time).total_seconds()
        assert abs(diff) < 1, diff

        local_epoch_start = datetime.datetime.fromtimestamp(0, datetime.timezone.utc)
        service_epoch_start = datetime.datetime.fromisoformat(definitely_1970)
        assert local_epoch_start == service_epoch_start, service_epoch_start
    return network


@reqs.description("Test metrics logging")
def test_metrics_logging(network, args):
    primary, _ = network.find_nodes()

    # Add and test on a new node, so we can kill it to safely read its logs
    new_node = network.create_node()
    network.join_node(
        new_node,
        args.package,
        args,
    )
    network.trust_node(new_node, args)

    # Submit several requests
    assertions = []
    with new_node.client() as c:
        c.get("/app/echo")
        assertions.append({"Method": "GET", "Path": "/app/echo"})
        c.post("/app/echo")
        assertions.append({"Method": "POST", "Path": "/app/echo"})
        c.get("/app/echo/hello")
        assertions.append({"Method": "GET", "Path": "/app/echo/{foo}"})
        c.post("/app/echo/bar")
        assertions.append({"Method": "POST", "Path": "/app/echo/{foo}"})
        c.get("/app/fibonacci/10")
        assertions.append({"Method": "GET", "Path": "/app/fibonacci/{n}"})
        c.get("/app/fibonacci/20")
        assertions.append({"Method": "GET", "Path": "/app/fibonacci/{n}"})
        c.get("/app/fibonacci/30")
        assertions.append({"Method": "GET", "Path": "/app/fibonacci/{n}"})

    # Remove node
    network.retire_node(primary, new_node)
    new_node.stop()

    # Read node's logs
    metrics_regex = re.compile(
        r".*\[js\].*\| JS execution complete: Method=(?P<Method>.*), Path=(?P<Path>.*), Status=(?P<Status>\d+), ExecMilliseconds=(?P<ExecMilliseconds>\d+)$"
    )
    out_path, _ = new_node.get_logs()
    for line in open(out_path, "r", encoding="utf-8").readlines():
        match = metrics_regex.match(line)
        if match is not None:
            expected_groups = assertions.pop(0)
            for k, v in expected_groups.items():
                actual_match = match.group(k)
                assert actual_match == v
            LOG.success(f"Found metrics logging line: {line}")
            LOG.info(f"Parsed to: {match.groups()}")

    assert len(assertions) == 0

    return network


def run_api(args):
    test_random_api(args)

    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        network = test_request_object_api(network, args)
        network = test_datetime_api(network, args)
        network = test_metrics_logging(network, args)


def test_reused_interpreter_behaviour(network, args):
    primary, _ = network.find_nodes()

    def timed(fn):
        start = datetime.datetime.now()
        result = fn()
        end = datetime.datetime.now()
        duration = (end - start).total_seconds()
        LOG.debug(f"({duration:.2f}s)")
        return duration, result

    # Extremely crude "same order-of-magnitude" comparisons
    def much_smaller(a, b):
        return a < b / 2

    # Not actual assertions because they'll often fail for unrelated
    # reasons - the JS execution got a caching benefit, but some
    # scheduling unluckiness caused the roundtrip time to be slow.
    # Instead we assert on the deterministic wasCached bool, but log
    # errors if this doesn't correspond with expected run time impact.
    def expect_much_smaller(a, b):
        if not (much_smaller(a, b)):
            LOG.error(
                f"Expected to complete much faster, but took {a:.4f} and {b:.4f} seconds"
            )

    def expect_similar(a, b):
        if much_smaller(a, b) or much_smaller(b, a):
            LOG.error(
                f"Expected similar execution times, but took {a:.4f} and {b:.4f} seconds"
            )

    def was_cached(response):
        return response.body.json()["wasCached"]

    fib_body = {"n": 25}

    with primary.client() as c:
        LOG.info("Testing with no caching benefit")
        baseline, res0 = timed(lambda: c.post("/fibonacci/reuse/none", fib_body))
        repeat1, res1 = timed(lambda: c.post("/fibonacci/reuse/none", fib_body))
        repeat2, res2 = timed(lambda: c.post("/fibonacci/reuse/none", fib_body))
        results = (res0, res1, res2)
        assert all(r.status_code == http.HTTPStatus.OK for r in results), results
        assert all(not was_cached(r) for r in results), results
        expect_similar(baseline, repeat1)
        expect_similar(baseline, repeat2)

        LOG.info("Testing cached interpreter benefit")
        baseline, res0 = timed(lambda: c.post("/fibonacci/reuse/a", fib_body))
        repeat1, res1 = timed(lambda: c.post("/fibonacci/reuse/a", fib_body))
        repeat2, res2 = timed(lambda: c.post("/fibonacci/reuse/a", fib_body))
        results = (res0, res1, res2)
        assert all(r.status_code == http.HTTPStatus.OK for r in results), results
        assert not was_cached(res0), res0
        assert was_cached(res1), res1
        assert was_cached(res2), res2
        expect_much_smaller(repeat1, baseline)
        expect_much_smaller(repeat2, baseline)

        LOG.info("Testing cached app behaviour")
        # For this app, different key means re-execution, so same as no cache benefit, first time
        baseline, res0 = timed(lambda: c.post("/fibonacci/reuse/a", {"n": 26}))
        repeat1, res1 = timed(lambda: c.post("/fibonacci/reuse/a", {"n": 26}))
        results = (res0, res1)
        assert all(r.status_code == http.HTTPStatus.OK for r in results), results
        assert not was_cached(res0), res0
        assert was_cached(res1), res1
        expect_much_smaller(repeat1, baseline)

        LOG.info("Testing behaviour of multiple interpreters")
        baseline, res0 = timed(lambda: c.post("/fibonacci/reuse/b", fib_body))
        repeat1, res1 = timed(lambda: c.post("/fibonacci/reuse/b", fib_body))
        repeat2, res2 = timed(lambda: c.post("/fibonacci/reuse/b", fib_body))
        results = (res0, res1, res2)
        assert all(r.status_code == http.HTTPStatus.OK for r in results), results
        assert not was_cached(res0), res0
        assert was_cached(res1), res1
        assert was_cached(res2), res2
        expect_much_smaller(repeat1, baseline)
        expect_much_smaller(repeat2, baseline)

        LOG.info("Testing cap on number of interpreters")
        # Call twice so we should definitely be cached, regardless of what previous tests did
        c.post("/fibonacci/reuse/a", fib_body)
        c.post("/fibonacci/reuse/b", fib_body)
        c.post("/fibonacci/reuse/c", fib_body)
        resa = c.post("/fibonacci/reuse/a", fib_body)
        resb = c.post("/fibonacci/reuse/b", fib_body)
        resc = c.post("/fibonacci/reuse/c", fib_body)
        results = (resa, resb, resc)
        assert all(was_cached(res) for res in results), results

        # Get current metrics to pass existing/default values
        r = c.get("/node/js_metrics")
        body = r.body.json()
        default_max_heap_size = body["max_heap_size"]
        default_max_stack_size = body["max_stack_size"]
        default_max_execution_time = body["max_execution_time"]
        default_max_cached_interpreters = body["max_cached_interpreters"]
        network.consortium.set_js_runtime_options(
            primary,
            max_heap_bytes=default_max_heap_size,
            max_stack_bytes=default_max_stack_size,
            max_execution_time_ms=default_max_execution_time,
            max_cached_interpreters=2,
        )

        # If we round-robin through too many interpreters, we flush them from the LRU cache
        c.post("/fibonacci/reuse/a", fib_body)
        c.post("/fibonacci/reuse/b", fib_body)
        c.post("/fibonacci/reuse/c", fib_body)
        resa = c.post("/fibonacci/reuse/a", fib_body)
        resb = c.post("/fibonacci/reuse/b", fib_body)
        resc = c.post("/fibonacci/reuse/c", fib_body)
        results = (resa, resb, resc)
        assert all(not was_cached(res) for res in results), results

        # But if we stay within the interpreter cap, then we get a cached interpreter
        resb = c.post("/fibonacci/reuse/b", fib_body)
        resc = c.post("/fibonacci/reuse/c", fib_body)
        results = (resb, resc)
        assert all(was_cached(res) for res in results), results

        # Restoring original cap
        network.consortium.set_js_runtime_options(
            primary,
            max_heap_bytes=default_max_heap_size,
            max_stack_bytes=default_max_stack_size,
            max_execution_time_ms=default_max_execution_time,
            max_cached_interpreters=default_max_cached_interpreters,
        )

        LOG.info("Testing Dependency Injection sample endpoint")
        baseline, res0 = timed(lambda: c.post("/app/di"))
        repeat1, res1 = timed(lambda: c.post("/app/di"))
        repeat2, res2 = timed(lambda: c.post("/app/di"))
        repeat3, res3 = timed(lambda: c.post("/app/di"))
        results = (res0, res1, res2, res3)
        assert all(r.status_code == http.HTTPStatus.OK for r in results), results
        expect_much_smaller(repeat1, baseline)
        expect_much_smaller(repeat2, baseline)
        expect_much_smaller(repeat3, baseline)

    return network


def test_caching_of_kv_handles(network, args):
    primary, _ = network.find_nodes()
    with primary.client() as c:
        LOG.info("Testing caching of KV handles")
        r = c.post("/app/increment")
        assert r.status_code == http.HTTPStatus.OK, r
        r = c.post("/app/increment")
        assert r.status_code == http.HTTPStatus.OK, r
        r = c.post("/app/increment")
        assert r.status_code == http.HTTPStatus.OK, r
        r = c.post("/app/increment")
        assert r.status_code == http.HTTPStatus.OK, r
        r = c.post("/app/increment")
        assert r.status_code == http.HTTPStatus.OK, r

        LOG.info("Testing caching of ccf JS globals")

        def make_body():
            return {str(uuid.uuid4()): str(uuid.uuid4())}

        body = make_body()
        r = c.post("/app/globals", body)
        assert r.status_code == http.HTTPStatus.OK, r
        assert r.body.json() == body

        body = make_body()
        r = c.post("/app/globals", body)
        assert r.status_code == http.HTTPStatus.OK, r
        assert r.body.json() == body

        body = make_body()
        r = c.post("/app/globals", body)
        assert r.status_code == http.HTTPStatus.OK, r
        assert r.body.json() == body

    return network


def test_caching_of_app_code(network, args):
    primary, backups = network.find_nodes()
    LOG.info(
        "Testing that interpreter reuse does not persist functions past app update"
    )

    def set_app_with_placeholder(new_val):
        LOG.info(f"Replacing placeholder with {new_val}")
        bundle = network.consortium.read_bundle_from_dir(args.js_app_bundle)
        # Replace placeholder blindly, in the raw bundle JSON as string
        s = json.dumps(bundle).replace("<func_caching_placeholder>", new_val)
        bundle = json.loads(s)
        return network.consortium.set_js_app_from_bundle(primary, bundle)

    for _ in range(5):
        v = str(uuid.uuid4())
        p = set_app_with_placeholder(v)
        for node in [primary, *backups]:
            with node.client() as c:
                infra.commit.wait_for_commit(client=c, view=p.view, seqno=p.seqno)
                r = c.get("/app/func_caching")
                assert r.status_code == http.HTTPStatus.OK, r
                assert r.body.text() == v

    return network


def run_interpreter_reuse(args):
    # The js_app_bundle arg includes TS and Node dependencies, so must be built here
    # before deploying (and then we deploy the produces /dist folder)
    js_src_dir = args.js_app_bundle
    LOG.info("Building mixed JS/TS app, with dependencies")
    subprocess.run(["npm", "install", "--no-package-lock"], cwd=js_src_dir, check=True)
    subprocess.run(["npm", "run", "build"], cwd=js_src_dir, check=True)
    args.js_app_bundle = os.path.join(js_src_dir, "dist")

    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        network = test_reused_interpreter_behaviour(network, args)  #
        network = test_caching_of_kv_handles(network, args)
        network = test_caching_of_app_code(network, args)


if __name__ == "__main__":
    cr = ConcurrentRunner()

    cr.add(
        "authz",
        run,
        nodes=infra.e2e_args.nodes(cr.args, 1),
        js_app_bundle=os.path.join(cr.args.js_app_bundle, "js-custom-authorization"),
    )

    cr.add(
        "limits",
        run_limits,
        nodes=infra.e2e_args.nodes(cr.args, 1),
        js_app_bundle=os.path.join(cr.args.js_app_bundle, "js-limits"),
    )

    cr.add(
        "authn",
        run_authn,
        nodes=infra.e2e_args.nodes(cr.args, 1),
        js_app_bundle=os.path.join(cr.args.js_app_bundle, "js-authentication"),
        initial_user_count=4,
        initial_member_count=2,
    )

    cr.add(
        "content_types",
        run_content_types,
        nodes=infra.e2e_args.nodes(cr.args, 1),
        js_app_bundle=os.path.join(cr.args.js_app_bundle, "js-content-types"),
    )

    cr.add(
        "api",
        run_api,
        nodes=infra.e2e_args.nodes(cr.args, 1),
        js_app_bundle=os.path.join(cr.args.js_app_bundle, "js-api"),
    )

    cr.add(
        "interpreter_reuse",
        run_interpreter_reuse,
        nodes=infra.e2e_args.min_nodes(cr.args, f=1),
        js_app_bundle=os.path.join(cr.args.js_app_bundle, "js-interpreter-reuse"),
    )

    cr.run()
