# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import tempfile
import json
import os
import threading
import time
import base64
import socket
from contextlib import contextmanager
import infra.network
import infra.jwt_issuer
import infra.path
import infra.proc
import infra.net
import infra.crypto
import infra.e2e_args
import infra.proposal
import suite.test_requirements as reqs
from infra.jwt_issuer import (
    OpenIDProviderServer,
    get_jwt_issuers,
    get_jwt_keys,
)
import ccf.ledger
from ccf.tx_id import TxID
import infra.clients

from loguru import logger as LOG

TRUST_STORE_LOCK = threading.Lock()


def set_issuer_with_keys(network, primary, issuer, kids):
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump({"issuer": issuer.name}, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(issuer.create_jwks_for_kids(kids), jwks_fp)
        jwks_fp.flush()

        network.consortium.set_jwt_public_signing_keys(
            primary, issuer.name, jwks_fp.name
        )


def assert_set_jwt_issuer_rejected(network, primary, metadata):
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump(metadata, metadata_fp)
        metadata_fp.flush()
        try:
            network.consortium.set_jwt_issuer(primary, metadata_fp.name)
        except infra.proposal.ProposalNotCreated as e:
            assert e.response.status_code == 400, e.response.body.text()
            assert (
                e.response.body.json()["error"]["code"] == "ProposalFailedToValidate"
            ), e.response.body.text()
        else:
            assert False, "set_jwt_issuer should have failed to validate"


@reqs.description("JWT issuer and JWKS validation")
def test_jwt_issuer_and_jwks_validation(network, args):
    primary, _ = network.find_nodes()
    issuer = infra.jwt_issuer.JwtIssuer("https://example.issuer")
    valid_key = issuer.create_jwks("kid1")["keys"][0]

    assert_set_jwt_issuer_rejected(network, primary, {"issuer": "example.issuer"})
    assert_set_jwt_issuer_rejected(
        network, primary, {"issuer": "https://example.issuer?foo=bar"}
    )
    assert_set_jwt_issuer_rejected(
        network, primary, {"issuer": "https://example.issuer#fragment"}
    )
    assert_set_jwt_issuer_rejected(
        network,
        primary,
        {"issuer": issuer.name, "jwks": {"keys": [valid_key, valid_key]}},
    )
    assert_set_jwt_issuer_rejected(
        network,
        primary,
        {"issuer": issuer.name, "jwks": {"keys": [{**valid_key, "kty": "oct"}]}},
    )
    assert_set_jwt_issuer_rejected(
        network,
        primary,
        {"issuer": issuer.name, "jwks": {"keys": [{**valid_key, "alg": "HS256"}]}},
    )
    assert_set_jwt_issuer_rejected(
        network,
        primary,
        {"issuer": issuer.name, "jwks": {"keys": [{**valid_key, "use": "enc"}]}},
    )

    # An RSA key (with n/e) tagged with an EC alg must be rejected even though
    # ES256 is otherwise an accepted alg value.
    assert_set_jwt_issuer_rejected(
        network,
        primary,
        {"issuer": issuer.name, "jwks": {"keys": [{**valid_key, "alg": "ES256"}]}},
    )

    # EC keys must have alg matching crv per RFC 7518 section 3.4: ES256 binds
    # to P-256, ES384 to P-384, ES512 to P-521. An ES256 alg on a P-256 key
    # should pass; any other alg on a P-256 key should be rejected.
    ec_issuer = infra.jwt_issuer.JwtIssuer(
        "https://example.issuer",
        alg=infra.jwt_issuer.JwtAlg.ES256,
        auth_type=infra.jwt_issuer.JwtAuthType.KEY,
    )
    ec_key = ec_issuer.create_jwks("kid1")["keys"][0]
    for wrong_alg in ("ES384", "ES512", "RS256"):
        assert_set_jwt_issuer_rejected(
            network,
            primary,
            {
                "issuer": ec_issuer.name,
                "jwks": {"keys": [{**ec_key, "alg": wrong_alg}]},
            },
        )


@reqs.description("Refresh JWT issuer")
def test_refresh_jwt_issuer(network, args):
    assert network.jwt_issuer.server, "JWT server is not started"
    network.jwt_issuer.refresh_keys()
    network.jwt_issuer.wait_for_refresh(network, args)

    # Check that more transactions can be issued
    network.txs.issue(network)
    return network


@reqs.description("Multiple JWT issuers can't share same kid different pem")
def test_jwt_mulitple_issuers_same_kids_different_pem(network, args):
    primary, _ = network.find_nodes()

    issuer1 = infra.jwt_issuer.JwtIssuer("https://example.issuer1")
    issuer2 = infra.jwt_issuer.JwtIssuer("https://example.issuer2")

    set_issuer_with_keys(network, primary, issuer1, ["kid1"])
    set_issuer_with_keys(network, primary, issuer2, ["kid1"])

    network.consortium.remove_jwt_issuer(primary, issuer1.name)
    network.consortium.remove_jwt_issuer(primary, issuer2.name)


@reqs.description("Multiple JWT issuers can share same kid same pem")
def test_jwt_mulitple_issuers_same_kids_same_pem(network, args):
    primary, _ = network.find_nodes()

    issuer1 = infra.jwt_issuer.JwtIssuer("https://example.issuer1")

    issuer2 = infra.jwt_issuer.JwtIssuer("https://example.issuer2")
    issuer2.cert_pem = issuer1.cert_pem

    set_issuer_with_keys(network, primary, issuer1, ["kid1"])
    set_issuer_with_keys(network, primary, issuer2, ["kid1"])

    network.consortium.remove_jwt_issuer(primary, issuer1.name)
    network.consortium.remove_jwt_issuer(primary, issuer2.name)


@reqs.description("Issuer constraint gets overwritten properly for same issuer+kid")
def test_jwt_same_issuer_constraint_overwritten(network, args):
    primary, _ = network.find_nodes()

    issuer = infra.jwt_issuer.JwtIssuer("https://example.issuer")
    keys = issuer.create_jwks_for_kids(["kid1"])

    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump({"issuer": issuer.name}, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(keys, jwks_fp)
        jwks_fp.flush()
        network.consortium.set_jwt_public_signing_keys(
            primary, issuer.name, jwks_fp.name
        )

    service_keys = get_jwt_keys(args, primary)
    assert service_keys["kid1"][0]["constraint"] == issuer.name

    new_constraint = "https://example.issuer/very/specific"
    keys["keys"][0]["issuer"] = new_constraint
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(keys, jwks_fp)
        jwks_fp.flush()
        network.consortium.set_jwt_public_signing_keys(
            primary, issuer.name, jwks_fp.name
        )

    service_keys = get_jwt_keys(args, primary)
    assert service_keys["kid1"][0]["constraint"] == new_constraint

    network.consortium.remove_jwt_issuer(primary, issuer.name)


@reqs.description("Only able to set keys with issuer constraints matching the url")
def test_jwt_issuer_domain_match(network, args):
    """Check domains match. Additional subdomains permitted. For example, https://limited.facebook.com
    may provide keys with issuer constraint https://facebook.com."""

    primary, _ = network.find_nodes()

    issuer = infra.jwt_issuer.JwtIssuer("https://trusted.issuer.com/something")
    keys = issuer.create_jwks_for_kids(["kid1"])

    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump({"issuer": issuer.name}, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(keys, jwks_fp)
        jwks_fp.flush()
        network.consortium.set_jwt_public_signing_keys(
            primary, issuer.name, jwks_fp.name
        )

    service_keys = get_jwt_keys(args, primary)
    assert service_keys["kid1"][0]["issuer"] == issuer.name

    keys["keys"][0]["issuer"] = "https://issuer.com"

    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(keys, jwks_fp)
        jwks_fp.flush()
        network.consortium.set_jwt_public_signing_keys(
            primary, issuer.name, jwks_fp.name
        )

    garbage = ["", "garbage", "https://another.com", "https://issuer.com.domain"]
    for constraint in garbage:
        with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
            keys["keys"][0]["issuer"] = constraint
            json.dump(keys, jwks_fp)
            jwks_fp.flush()
            try:
                network.consortium.set_jwt_public_signing_keys(
                    primary, issuer.name, jwks_fp.name
                )
            except infra.proposal.ProposalNotAccepted:
                pass
            else:
                assert False, f"Constraint {constraint} must not be allowed"

    network.consortium.remove_jwt_issuer(primary, issuer.name)


@reqs.description("Multiple JWT issuers registered at once")
def test_jwt_endpoint(network, args):
    primary, _ = network.find_nodes()

    keys = {
        infra.jwt_issuer.JwtIssuer("https://example.issuer1"): [
            "issuer1_kid1",
            "issuer1_kid2",
        ],
        infra.jwt_issuer.JwtIssuer("https://example.issuer2"): [
            "issuer2_kid1",
            "issuer2_kid2",
        ],
    }

    LOG.info("Register JWT issuer with multiple kids")
    for issuer, kids in keys.items():
        set_issuer_with_keys(network, primary, issuer, kids)

    LOG.info("Check that JWT endpoint returns all keys and issuers")
    service_issuers = get_jwt_issuers(args, primary)
    service_keys = get_jwt_keys(args, primary)

    for issuer, kids in keys.items():
        assert issuer.name in service_issuers, service_issuers
        for kid in kids:
            assert kid in service_keys, service_keys
            assert service_keys[kid][0]["issuer"] == issuer.name
            assert service_keys[kid][0]["constraint"] == issuer.name
            assert service_keys[kid][0]["publicKey"] == issuer.key_pub_pem
            assert "certificate" not in service_keys[kid][0]


@reqs.description("JWT without key policy")
def test_jwt_without_key_policy(network, args):
    primary, _ = network.find_nodes()

    issuer = infra.jwt_issuer.JwtIssuer("https://example.issuer")
    kid = "my_kid_not_key_policy"

    network.consortium.remove_jwt_issuer(primary, issuer.name)

    LOG.info("Try to add JWT signing key without matching issuer")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(issuer.create_jwks(kid), jwks_fp)
        jwks_fp.flush()
        try:
            network.consortium.set_jwt_public_signing_keys(
                primary, issuer.name, jwks_fp.name
            )
        except infra.proposal.ProposalNotAccepted:
            pass
        else:
            assert False, "Proposal should not have been created"

    LOG.info("Add JWT issuer")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump({"issuer": issuer.name}, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    LOG.info("Try to add a public key instead of a certificate")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        jwks = issuer.create_jwks(kid)
        der_b64 = base64.b64encode(
            infra.crypto.pub_key_pem_to_der(issuer.key_pub_pem)
        ).decode("ascii")
        jwks["keys"][0]["x5c"] = [der_b64]
        json.dump(jwks, jwks_fp)
        jwks_fp.flush()
        try:
            network.consortium.set_jwt_public_signing_keys(
                primary, issuer.name, jwks_fp.name
            )
        except (infra.proposal.ProposalNotAccepted, infra.proposal.ProposalNotCreated):
            pass
        else:
            assert False, "Proposal should not have been created"

    LOG.info("Add JWT signing key with matching issuer")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(issuer.create_jwks(kid), jwks_fp)
        jwks_fp.flush()
        network.consortium.set_jwt_public_signing_keys(
            primary, issuer.name, jwks_fp.name
        )

        keys = get_jwt_keys(args, primary)
        stored_key = keys[kid][0]["publicKey"]

        assert stored_key == issuer.key_pub_pem, "input key is not equal to stored key"

    LOG.info("Remove JWT issuer")
    network.consortium.remove_jwt_issuer(primary, issuer.name)

    keys = get_jwt_keys(args, primary)
    assert (
        kid not in keys
    ), f"JWT key associated with issuer {issuer.name} was not removed: {keys[kid]}"

    LOG.info("Add JWT issuer with initial keys")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump({"issuer": issuer.name, "jwks": issuer.create_jwks(kid)}, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

        keys = get_jwt_keys(args, primary)
        stored_key = keys[kid][0]["publicKey"]

        assert stored_key == issuer.key_pub_pem, "input key is not equal to stored key"

    return network


def check_kv_jwt_key_matches(args, network, kid, key_pem):
    primary, _ = network.find_nodes()
    latest_jwt_signing_keys = get_jwt_keys(args, primary)

    if key_pem is None:
        assert kid not in latest_jwt_signing_keys
    else:
        # Necessary to get an AssertionError if the key is not found yet,
        # when used from with_timeout()
        assert kid in latest_jwt_signing_keys
        stored_key = latest_jwt_signing_keys[kid][0]["publicKey"]
        assert stored_key == key_pem, "input cert is not equal to stored cert"


def check_kv_jwt_key_constraint(args, network, kid, expected_constraint):
    primary, _ = network.find_nodes()
    latest_jwt_signing_keys = get_jwt_keys(args, primary)

    assert kid in latest_jwt_signing_keys
    stored_constraint = latest_jwt_signing_keys[kid][0]["constraint"]
    assert stored_constraint == expected_constraint


def check_kv_jwt_keys_not_empty(args, network, issuer):
    primary, _ = network.find_nodes()
    latest_jwt_signing_keys = get_jwt_keys(args, primary)

    for _, data in latest_jwt_signing_keys.items():
        for key in data:
            if key["issuer"] == issuer:
                return

    assert False, "No keys for issuer"


def get_jwt_refresh_endpoint_metrics(primary) -> dict:
    # Note that these metrics are local to a node. So if the primary changes, or
    # a different node has processed jwt_keys/refresh, you may not see the values
    # you expect
    with primary.client() as c:
        r = c.get("/node/jwt_keys/refresh/metrics")
        assert r.status_code == 200, r
        return r.body.json()


@contextmanager
def reserve_unlistened_local_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        yield s.getsockname()[1]


def trust_jwt_issuer(args, issuer):
    trust_store = getattr(args, "jwt_test_trust_store", None)
    if trust_store:
        with TRUST_STORE_LOCK:
            with open(trust_store, "a", encoding="utf-8") as f:
                f.write(issuer.tls_cert)
                f.write("\n")


def add_auto_refresh_jwt_issuer(network, args, primary, issuer):
    trust_jwt_issuer(args, issuer)
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump(
            {
                "issuer": issuer.name,
                "auto_refresh": True,
            },
            metadata_fp,
        )
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)


def remove_all_jwt_issuers(network, args, primary):
    for issuer in list(get_jwt_issuers(args, primary)):
        network.consortium.remove_jwt_issuer(primary, issuer)


def check_refresh_failures_increased(primary, failures_before):
    m = get_jwt_refresh_endpoint_metrics(primary)
    assert m["failures"] > failures_before, m


def test_jwt_key_auto_refresh_connection_failure(network, args):
    primary, _ = network.find_nodes()
    remove_all_jwt_issuers(network, args, primary)
    failures_before = get_jwt_refresh_endpoint_metrics(primary)["failures"]
    issuer_host = "127.0.0.1"

    LOG.info("Add JWT issuer with auto-refresh pointing at an unavailable endpoint")
    with reserve_unlistened_local_port() as issuer_port:
        issuer = infra.jwt_issuer.JwtIssuer(
            f"https://{issuer_host}:{issuer_port}", cn=issuer_host
        )
        add_auto_refresh_jwt_issuer(network, args, primary, issuer)
        try:
            with_timeout(
                lambda: check_refresh_failures_increased(primary, failures_before),
                timeout=5,
            )
        finally:
            network.consortium.remove_jwt_issuer(primary, issuer.name)


def test_jwt_key_auto_refresh_tls_failure(network, args):
    primary, _ = network.find_nodes()
    remove_all_jwt_issuers(network, args, primary)
    failures_before = get_jwt_refresh_endpoint_metrics(primary)["failures"]
    issuer = infra.jwt_issuer.JwtIssuer("https://localhost", cn="localhost")

    # Do not add this issuer to args.jwt_test_trust_store. This verifies that
    # nodes use the configured SSL_CERT_FILE trust store for JWT auto-refresh.
    LOG.info("Start OpenID endpoint server with a certificate not in the system store")
    with issuer.start_openid_server(0) as server:
        issuer_name = f"https://localhost:{server.bind_port}"
        with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
            json.dump(
                {
                    "issuer": issuer_name,
                    "auto_refresh": True,
                },
                metadata_fp,
            )
            metadata_fp.flush()
            network.consortium.set_jwt_issuer(primary, metadata_fp.name)

        try:
            with_timeout(
                lambda: check_refresh_failures_increased(primary, failures_before),
                timeout=5,
            )
        finally:
            network.consortium.remove_jwt_issuer(primary, issuer_name)


def test_jwt_key_auto_refresh_invalid_metadata_issuer(network, args):
    primary, _ = network.find_nodes()
    remove_all_jwt_issuers(network, args, primary)
    failures_before = get_jwt_refresh_endpoint_metrics(primary)["failures"]
    issuer = infra.jwt_issuer.JwtIssuer("https://localhost", cn="localhost")
    trust_jwt_issuer(args, issuer)

    LOG.info("Start OpenID endpoint server with a non-string issuer metadata field")
    with issuer.start_openid_server(0) as server:
        issuer_name = f"https://localhost:{server.bind_port}"
        server.metadata["issuer"] = {"unexpected": "object"}

        with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
            json.dump(
                {
                    "issuer": issuer_name,
                    "auto_refresh": True,
                },
                metadata_fp,
            )
            metadata_fp.flush()
            network.consortium.set_jwt_issuer(primary, metadata_fp.name)

        try:
            with_timeout(
                lambda: check_refresh_failures_increased(primary, failures_before),
                timeout=5,
            )
        finally:
            network.consortium.remove_jwt_issuer(primary, issuer_name)


def test_jwt_key_auto_refresh_cross_authority_jwks_uri(network, args):
    primary, _ = network.find_nodes()
    remove_all_jwt_issuers(network, args, primary)
    issuer_host = "localhost"
    issuer = infra.jwt_issuer.JwtIssuer(f"https://{issuer_host}", cn=issuer_host)
    trust_jwt_issuer(args, issuer)
    kid = "cross_authority_jwks_uri"

    LOG.info("Start OpenID endpoint server with cross-authority JWKS URI")
    with issuer.start_openid_server(0, kid) as server, OpenIDProviderServer(
        0, issuer.tls_priv, issuer.tls_cert, issuer.create_jwks(kid)
    ) as jwks_server:
        issuer.name = f"https://{issuer_host}:{server.bind_port}"
        issuer_name = issuer.name
        # Exercise OIDC-compatible metadata where JWKS are served from a
        # different authority than the issuer metadata.
        server.metadata["jwks_uri"] = f"https://localhost:{jwks_server.bind_port}/keys"

        with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
            json.dump(
                {
                    "issuer": issuer_name,
                    "auto_refresh": True,
                },
                metadata_fp,
            )
            metadata_fp.flush()
            network.consortium.set_jwt_issuer(primary, metadata_fp.name)

        try:
            with_timeout(
                lambda: check_kv_jwt_key_matches(
                    args, network, kid, issuer.key_pub_pem
                ),
                timeout=15,
            )
        finally:
            network.consortium.remove_jwt_issuer(primary, issuer_name)


def test_jwt_key_auto_refresh_response_size_limit(network, args):
    primary, _ = network.find_nodes()
    remove_all_jwt_issuers(network, args, primary)
    failures_before = get_jwt_refresh_endpoint_metrics(primary)["failures"]
    issuer = infra.jwt_issuer.JwtIssuer("https://localhost", cn="localhost")
    kid = "response_size_limit"

    LOG.info("Start OpenID endpoint server with oversized metadata")
    with issuer.start_openid_server(0, kid) as server:
        issuer.name = f"https://localhost:{server.bind_port}"
        server.metadata["oversized_response"] = "x" * 4096
        add_auto_refresh_jwt_issuer(network, args, primary, issuer)

        try:
            with_timeout(
                lambda: check_refresh_failures_increased(primary, failures_before),
                timeout=5,
            )

            LOG.info("Restore OpenID metadata and re-add JWT issuer")
            del server.metadata["oversized_response"]
            network.consortium.remove_jwt_issuer(primary, issuer.name)
            add_auto_refresh_jwt_issuer(network, args, primary, issuer)

            with_timeout(
                lambda: check_kv_jwt_key_matches(
                    args, network, kid, issuer.key_pub_pem
                ),
                timeout=15,
            )
        finally:
            network.consortium.remove_jwt_issuer(primary, issuer.name)


@reqs.description("JWT with auto_refresh enabled")
def test_jwt_key_auto_refresh(network, args):
    primary, _ = network.find_nodes()

    kid = "the_kid"
    issuer_host = "localhost"
    issuer_port = args.issuer_port

    issuer = infra.jwt_issuer.JwtIssuer(
        f"https://{issuer_host}:{issuer_port}", cn=issuer_host
    )

    trust_jwt_issuer(args, issuer)

    LOG.info("Start OpenID endpoint server")
    # Capture baseline metrics before the server starts: any connection failures
    # from a prior test run (e.g. after a primary failover when the server was
    # briefly unavailable) will already be reflected here and must not be counted
    # as failures introduced by this test.
    baseline_m = get_jwt_refresh_endpoint_metrics(primary)
    with issuer.start_openid_server(issuer_port, kid) as server:
        # Send oversized headers with the payload that will cause the CCF client to
        # fail parsing and log an error.
        server.inject_oversized_header = True
        req_count = server.request_count
        LOG.info("Add JWT issuer with auto-refresh")
        with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
            json.dump(
                {
                    "issuer": issuer.name,
                    "auto_refresh": True,
                },
                metadata_fp,
            )
            metadata_fp.flush()
            network.consortium.set_jwt_issuer(primary, metadata_fp.name)

            # Make sure we did serve at least one request with oversized headers to CCF before
            # reverting to normal headers.
            def assert_request_count_increased():
                assert (
                    server.request_count > req_count
                ), "No request was served with oversized headers"

            with_timeout(assert_request_count_increased, timeout=1)

            with_timeout(
                lambda: check_refresh_failures_increased(
                    primary, baseline_m["failures"]
                ),
                timeout=5,
            )
            server.inject_oversized_header = False

            LOG.info("Check that keys got refreshed")
            # Note: refresh interval is set to 1s, see network args below.
            with_timeout(
                lambda: check_kv_jwt_key_matches(
                    args, network, kid, issuer.key_pub_pem
                ),
                timeout=5,
            )
            check_kv_jwt_key_constraint(args, network, kid, issuer.name)

        LOG.info("Check that JWT refresh has attempts and successes")
        m = get_jwt_refresh_endpoint_metrics(primary)
        assert m["attempts"] > baseline_m["attempts"], m
        assert m["successes"] > baseline_m["successes"], m
        failures = m["failures"]

        LOG.info("Serve invalid JWKS")
        server.jwks = {"foo": "bar"}

        LOG.info("Check that JWT refresh endpoint has more failures")

        def check_has_failures():
            m = get_jwt_refresh_endpoint_metrics(primary)
            assert m["failures"] > failures, m

        with_timeout(check_has_failures, timeout=5)

        LOG.info("Check that JWT refresh has fewer successes than attempts")
        m = get_jwt_refresh_endpoint_metrics(primary)
        assert m["attempts"] > m["successes"], m

    LOG.info("Restart OpenID endpoint server with new keys")
    kid2 = "the_kid_2"
    issuer.refresh_keys(kid2)
    with issuer.start_openid_server(issuer_port, kid2):
        LOG.info("Check that keys got refreshed")
        with_timeout(
            lambda: check_kv_jwt_key_matches(args, network, kid, None), timeout=5
        )
        check_kv_jwt_key_matches(args, network, kid2, issuer.key_pub_pem)

    return network


@reqs.description("JWT with auto_refresh enabled, check for duplicate entries")
def test_jwt_key_auto_refresh_entries(network, args):
    primary, _ = network.find_nodes()

    kid = "the_kid_no_duplicates"
    issuer_host = "localhost"
    issuer_port = args.issuer_port

    issuer = infra.jwt_issuer.JwtIssuer(
        f"https://{issuer_host}:{issuer_port}", cn=issuer_host
    )

    trust_jwt_issuer(args, issuer)

    LOG.info("Start OpenID endpoint server")
    with issuer.start_openid_server(issuer_port, kid):
        LOG.info("Add JWT issuer with auto-refresh")
        with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
            json.dump(
                {
                    "issuer": issuer.name,
                    "auto_refresh": True,
                },
                metadata_fp,
            )
            metadata_fp.flush()
            network.consortium.set_jwt_issuer(primary, metadata_fp.name)

            LOG.info("Check that keys got refreshed")
            # Note: refresh interval is set to 1s, see network args below.
            with_timeout(
                lambda: check_kv_jwt_key_matches(
                    args, network, kid, issuer.key_pub_pem
                ),
                timeout=5,
            )

        LOG.info("Check that JWT refresh has attempts and successes")
        m = get_jwt_refresh_endpoint_metrics(primary)
        attempts = m["attempts"]
        successes = m["successes"]
        assert attempts > 0, attempts
        assert successes > 0, successes

        def check_refresh_progressed():
            m = get_jwt_refresh_endpoint_metrics(primary)
            assert m["attempts"] > attempts, m["attempts"]
            assert m["successes"] > successes, m["successes"]

        with_timeout(
            check_refresh_progressed,
            timeout=max(5, args.jwt_key_refresh_interval_s * 5),
        )

        # Force chunking
        network.get_latest_ledger_public_state()
        # Check that despite refreshing JWTs multiple times, only a single
        # transaction was created for this kid.
        ledger_directories = primary.remote.ledger_paths()
        ledger = ccf.ledger.Ledger(ledger_directories, contiguous_suffix=True)

        last_key_refresh = None
        for chunk in ledger:
            for tx in chunk:
                txid = TxID(tx.gcm_header.view, tx.gcm_header.seqno)
                tables = tx.get_public_domain().get_tables()
                if "public:ccf.gov.jwt.public_signing_keys_metadata_v2" in tables:
                    pub_keys = tables[
                        "public:ccf.gov.jwt.public_signing_keys_metadata_v2"
                    ]
                    if kid.encode() in pub_keys:
                        if last_key_refresh is None:
                            LOG.info(f"Refresh found for kid: {kid} at {txid}")
                            last_key_refresh = txid
                        else:
                            assert (
                                last_key_refresh == txid
                            ), "Duplicate JWT refresh transaction"
        assert last_key_refresh, "Missing JWT refresh transaction"

    return network


@reqs.description("JWT with auto_refresh enabled, initial refresh")
def test_jwt_key_initial_refresh(network, args, timeout_s=15):
    primary, _ = network.find_nodes()

    kid = f"my_kid_autorefresh_{primary.local_node_id}"
    issuer_host = "localhost"
    issuer_port = args.issuer_port

    issuer = infra.jwt_issuer.JwtIssuer(
        f"https://{issuer_host}:{issuer_port}", cn=issuer_host
    )

    trust_jwt_issuer(args, issuer)

    LOG.info("Start OpenID endpoint server")
    with issuer.start_openid_server(issuer_port, kid):
        LOG.info("Add JWT issuer with auto-refresh")
        with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
            json.dump(
                {
                    "issuer": issuer.name,
                    "auto_refresh": True,
                },
                metadata_fp,
            )
            metadata_fp.flush()
            network.consortium.set_jwt_issuer(primary, metadata_fp.name)

        LOG.info("Check that keys got refreshed")
        # Auto-refresh interval has been set to a large value so that it doesn't happen within the timeout.
        # This is testing the one-off refresh after adding a new issuer.
        # The timeout is generous because this check also runs straight after a
        # primary failover, where the newly-elected primary must restart the
        # refresh and re-fetch the keys, which can take several seconds under CI
        # load.
        with_timeout(
            lambda: check_kv_jwt_key_matches(args, network, kid, issuer.key_pub_pem),
            timeout=timeout_s,
        )

        LOG.info("Check that JWT refresh endpoint has no failures")
        m = get_jwt_refresh_endpoint_metrics(primary)
        assert m["failures"] == 0, m["failures"]
        assert m["successes"] > 0, m["successes"]

    return network


def test_jwt_key_refresh_aad(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Check JWT auto-refresh against Entra using the system trust store")
    issuer = "https://login.microsoftonline.com/common/v2.0/"
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump(
            {
                "issuer": issuer,
                "auto_refresh": True,
            },
            metadata_fp,
        )
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    LOG.info("Check that keys got refreshed")
    with_timeout(lambda: check_kv_jwt_keys_not_empty(args, network, issuer), timeout=5)

def test_malformed_tokens(network, args):
    primary, _ = network.find_nodes()

    with primary.client() as c:
        malformed_tokens = [
            (
                "abc.def",
                "Malformed JWT: must contain exactly 3 parts",
            ),
            (
                "abc.def.ghi.jkl",
                "Malformed JWT: must contain exactly 3 parts",
            ),
            (
                "Zm9v.YmF6.=wwy",
                "Failed to parse base64url in JWT (signature)",
            ),
            (
                "Zm9v.=wwy.YmF6",
                "Failed to parse base64url in JWT (payload)",
            ),
            (
                "=wwy.Zm9v.YmF6",
                "Failed to parse base64url in JWT (header)",
            ),
            (
                ".abc.abc",
                "JWT part is empty (header)",
            ),
            (
                "abc..abc",
                "JWT part is empty (payload)",
            ),
            (
                "abc.abc.",
                "JWT part is empty (signature)",
            ),
        ]

        for token, message in malformed_tokens:
            r = c.get("/app/log/public", headers={"authorization": f"Bearer {token}"})
            assert (
                r.status_code == 401
            ), f"Unexpected status code for token {token}: {r}"
            error = r.body.json().get("error")
            assert error["code"] == "InvalidAuthenticationInfo"
            details = {
                detail["auth_policy"]: detail for detail in error.get("details", [])
            }
            assert details["jwt"]["message"] == message, r


def with_timeout(fn, timeout):
    t0 = time.time()
    while True:
        try:
            return fn()
        except (TimeoutError, AssertionError):
            if time.time() - t0 < timeout:
                time.sleep(0.1)
            else:
                raise


def run_auto(args):
    with tempfile.NamedTemporaryFile(prefix="ccf_jwt_trust_", mode="w+") as trust_store:
        args.jwt_test_trust_store = trust_store.name
        with infra.network.network(
            args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
        ) as network:
            network.start_and_open(
                args, env=os.environ | {"SSL_CERT_FILE": trust_store.name}
            )
            test_jwt_issuer_and_jwks_validation(network, args)
            test_jwt_mulitple_issuers_same_kids_different_pem(network, args)
            test_jwt_mulitple_issuers_same_kids_same_pem(network, args)
            test_jwt_same_issuer_constraint_overwritten(network, args)
            test_jwt_issuer_domain_match(network, args)
            test_jwt_endpoint(network, args)
            test_jwt_without_key_policy(network, args)
            test_jwt_key_auto_refresh(network, args)

            # Check that auto refresh also works on backups
            primary, _ = network.find_primary()
            primary.stop()
            network.wait_for_new_primary(primary)
            test_jwt_key_auto_refresh(network, args)
            # Check that we can refresh keys for Entra endpoint
            test_jwt_key_refresh_aad(network, args)
            test_jwt_key_auto_refresh_entries(network, args)

            test_malformed_tokens(network, args)


def run_manual(args):
    with tempfile.NamedTemporaryFile(prefix="ccf_jwt_trust_", mode="w+") as trust_store:
        args.jwt_test_trust_store = trust_store.name
        with infra.network.network(
            args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
        ) as network:
            network.start_and_open(
                args, env=os.environ | {"SSL_CERT_FILE": trust_store.name}
            )
            test_jwt_key_initial_refresh(network, args)

            # Check that initial refresh also works on backups
            primary, _ = network.find_primary()
            primary.stop()
            network.wait_for_new_primary(primary)
            test_jwt_key_initial_refresh(network, args, timeout_s=30)
            test_jwt_key_auto_refresh_connection_failure(network, args)
            test_jwt_key_auto_refresh_tls_failure(network, args)
            test_jwt_key_auto_refresh_invalid_metadata_issuer(network, args)
            test_jwt_key_auto_refresh_cross_authority_jwks_uri(network, args)
            test_jwt_key_auto_refresh_response_size_limit(network, args)
