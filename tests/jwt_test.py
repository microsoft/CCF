# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import tempfile
import json
import time
import base64
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.crypto
import infra.e2e_args
import infra.proposal
import suite.test_requirements as reqs
from infra.jwt_issuer import get_jwt_issuers, get_jwt_keys
from infra.runner import ConcurrentRunner
import ca_certs
import ccf.ledger
from ccf.tx_id import TxID
import infra.clients

from loguru import logger as LOG


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


@reqs.description("JWT with auto_refresh enabled")
def test_jwt_key_auto_refresh(network, args):
    primary, _ = network.find_nodes()

    ca_cert_bundle_name = "jwt"
    kid = "the_kid"
    issuer_host = "localhost"
    issuer_port = args.issuer_port

    issuer = infra.jwt_issuer.JwtIssuer(
        f"https://{issuer_host}:{issuer_port}", cn=issuer_host
    )

    LOG.info("Add CA cert for JWT issuer")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as ca_cert_bundle_fp:
        ca_cert_bundle_fp.write(issuer.tls_cert)
        ca_cert_bundle_fp.flush()
        network.consortium.set_ca_cert_bundle(
            primary, ca_cert_bundle_name, ca_cert_bundle_fp.name
        )

    LOG.info("Start OpenID endpoint server")
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
                    "ca_cert_bundle_name": ca_cert_bundle_name,
                },
                metadata_fp,
            )
            metadata_fp.flush()
            network.consortium.set_jwt_issuer(primary, metadata_fp.name)
            # Make sure we did serve at least one request with oversized headers to CCF before
            # reverting to normal headers.
            assert (
                server.request_count > req_count
            ), "No request was served with oversized headers"
            server.inject_oversized_header = False

            LOG.info("Check that keys got refreshed")
            # Note: refresh interval is set to 1s, see network args below.
            with_timeout(
                lambda: check_kv_jwt_key_matches(
                    args, network, kid, issuer.key_pub_pem
                ),
                timeout=5,
            )

        LOG.info("Check that JWT refresh has attempts and successes and no failures")
        m = get_jwt_refresh_endpoint_metrics(primary)
        assert m["attempts"] > 0, m
        assert m["successes"] > 0, m
        assert m["failures"] == 0, m

        LOG.info("Serve invalid JWKS")
        server.jwks = {"foo": "bar"}

        LOG.info("Check that JWT refresh endpoint has some failures")

        def check_has_failures():
            m = get_jwt_refresh_endpoint_metrics(primary)
            assert m["failures"] > 0, m

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

    ca_cert_bundle_name = "jwt"
    kid = "the_kid_no_duplicates"
    issuer_host = "localhost"
    issuer_port = args.issuer_port

    issuer = infra.jwt_issuer.JwtIssuer(
        f"https://{issuer_host}:{issuer_port}", cn=issuer_host
    )

    LOG.info("Add CA cert for JWT issuer")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as ca_cert_bundle_fp:
        ca_cert_bundle_fp.write(issuer.tls_cert)
        ca_cert_bundle_fp.flush()
        network.consortium.set_ca_cert_bundle(
            primary, ca_cert_bundle_name, ca_cert_bundle_fp.name
        )

    LOG.info("Start OpenID endpoint server")
    with issuer.start_openid_server(issuer_port, kid):
        LOG.info("Add JWT issuer with auto-refresh")
        with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
            json.dump(
                {
                    "issuer": issuer.name,
                    "auto_refresh": True,
                    "ca_cert_bundle_name": ca_cert_bundle_name,
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

        # Wait long enough for at least one refresh to take place
        time.sleep(args.jwt_key_refresh_interval_s)

        m = get_jwt_refresh_endpoint_metrics(primary)
        assert m["attempts"] > attempts, m["attempts"]
        assert m["successes"] > successes, m["successes"]

        # Force chunking
        network.get_latest_ledger_public_state()
        # Check that despite refreshing JWTs multiple times, only a single
        # transaction was created for this kid.
        ledger_directories = primary.remote.ledger_paths()
        ledger = ccf.ledger.Ledger(ledger_directories)

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
def test_jwt_key_initial_refresh(network, args):
    primary, _ = network.find_nodes()

    ca_cert_bundle_name = "jwt"
    kid = f"my_kid_autorefresh_{primary.local_node_id}"
    issuer_host = "localhost"
    issuer_port = args.issuer_port

    issuer = infra.jwt_issuer.JwtIssuer(
        f"https://{issuer_host}:{issuer_port}", cn=issuer_host
    )

    LOG.info("Add CA cert for JWT issuer")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as ca_cert_bundle_fp:
        ca_cert_bundle_fp.write(issuer.tls_cert)
        ca_cert_bundle_fp.flush()
        network.consortium.set_ca_cert_bundle(
            primary, ca_cert_bundle_name, ca_cert_bundle_fp.name
        )

    LOG.info("Start OpenID endpoint server")
    with issuer.start_openid_server(issuer_port, kid):
        LOG.info("Add JWT issuer with auto-refresh")
        with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
            json.dump(
                {
                    "issuer": issuer.name,
                    "auto_refresh": True,
                    "ca_cert_bundle_name": ca_cert_bundle_name,
                },
                metadata_fp,
            )
            metadata_fp.flush()
            network.consortium.set_jwt_issuer(primary, metadata_fp.name)

        LOG.info("Check that keys got refreshed")
        # Auto-refresh interval has been set to a large value so that it doesn't happen within the timeout.
        # This is testing the one-off refresh after adding a new issuer.
        with_timeout(
            lambda: check_kv_jwt_key_matches(args, network, kid, issuer.key_pub_pem),
            timeout=5,
        )

        LOG.info("Check that JWT refresh endpoint has no failures")
        m = get_jwt_refresh_endpoint_metrics(primary)
        assert m["failures"] == 0, m["failures"]
        assert m["successes"] > 0, m["successes"]

    return network


# Root CA for login.microsoftonline.com:443
# Used as root of trust by CCF (after being set via set_ca_cert_bundle)
# for the purpose of fetching JWK list and JWKs
DIGICERT_GLOBAL_ROOT_CA = """-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB
CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97
nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt
43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P
T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4
gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO
BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR
TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw
DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
-----END CERTIFICATE-----"""

DIGICERT_GLOBAL_ROOT_G2_CA = """-----BEGIN CERTIFICATE-----
MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI
2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx
1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ
q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz
tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ
vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV
5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY
1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4
NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG
Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91
8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe
pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl
MrY=
-----END CERTIFICATE-----"""


def test_jwt_key_refresh_aad(network, args, ascending=True):
    primary, _ = network.find_nodes()

    LOG.info("Add CA cert for Entra JWT issuer")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as ca_cert_bundle_fp:
        if ascending:
            ca_cert_bundle_fp.write(DIGICERT_GLOBAL_ROOT_CA)
            ca_cert_bundle_fp.write("\n")
            ca_cert_bundle_fp.write(DIGICERT_GLOBAL_ROOT_G2_CA)
        else:
            ca_cert_bundle_fp.write(DIGICERT_GLOBAL_ROOT_G2_CA)
            ca_cert_bundle_fp.write("\n")
            ca_cert_bundle_fp.write(DIGICERT_GLOBAL_ROOT_CA)
        ca_cert_bundle_fp.flush()
        network.consortium.set_ca_cert_bundle(primary, "aad", ca_cert_bundle_fp.name)

    issuer = "https://login.microsoftonline.com/common/v2.0/"
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump(
            {
                "issuer": issuer,
                "auto_refresh": True,
                "ca_cert_bundle_name": "aad",
            },
            metadata_fp,
        )
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    LOG.info("Check that keys got refreshed")
    with_timeout(lambda: check_kv_jwt_keys_not_empty(args, network, issuer), timeout=5)


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
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
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
        test_jwt_key_refresh_aad(network, args, ascending=True)
        test_jwt_key_refresh_aad(network, args, ascending=False)
        test_jwt_key_auto_refresh_entries(network, args)


def run_manual(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        test_jwt_key_initial_refresh(network, args)

        # Check that initial refresh also works on backups
        primary, _ = network.find_primary()
        primary.stop()
        network.wait_for_new_primary(primary)
        test_jwt_key_initial_refresh(network, args)


def run_ca_cert(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        ca_certs.test_cert_store(network, args)


if __name__ == "__main__":
    cr = ConcurrentRunner()

    cr.add(
        "auto",
        run_auto,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=1),
        jwt_key_refresh_interval_s=1,
        issuer_port=12345,
    )

    cr.add(
        "manual",
        run_manual,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=1),
        jwt_key_refresh_interval_s=100000,
        issuer_port=12346,
    )

    cr.add(
        "ca_cert",
        run_ca_cert,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.max_nodes(cr.args, f=0),
    )

    cr.run()
