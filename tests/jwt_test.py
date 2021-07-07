# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import tempfile
import json
import time
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs
import infra.jwt_issuer

from loguru import logger as LOG

this_dir = os.path.dirname(__file__)


@reqs.description("Refresh JWT issuer")
def test_refresh_jwt_issuer(network, args):
    assert network.jwt_issuer.server, "JWT server is not started"
    network.jwt_issuer.refresh_keys()
    network.jwt_issuer.wait_for_refresh(network)

    # Check that more transactions can be issued
    network.txs.issue(network)
    return network


@reqs.description("JWT without key policy")
def test_jwt_without_key_policy(network, args):
    primary, _ = network.find_nodes()

    issuer = infra.jwt_issuer.JwtIssuer("my_issuer")
    kid = "my_kid"

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
        json.dump(issuer.create_jwks(kid, test_invalid_is_key=True), jwks_fp)
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

        with primary.client(network.consortium.get_any_active_member().local_id) as c:
            r = c.get("/gov/jwt_keys/all")
            assert r.status_code == 200, r
            stored_cert = r.body.json()[kid]

        assert infra.crypto.are_certs_equal(
            issuer.cert_pem, stored_cert
        ), "input cert is not equal to stored cert"

    LOG.info("Remove JWT issuer")
    network.consortium.remove_jwt_issuer(primary, issuer.name)

    with primary.client(network.consortium.get_any_active_member().local_id) as c:
        r = c.get("/gov/jwt_keys/all")
        assert r.status_code == 200, r
        assert (
            kid not in r.body.json()
        ), f"JWT issuer was not removed {r.body.json()[kid]}"

    LOG.info("Add JWT issuer with initial keys")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump({"issuer": issuer.name, "jwks": issuer.create_jwks(kid)}, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

        with primary.client(network.consortium.get_any_active_member().local_id) as c:
            r = c.get("/gov/jwt_keys/all")
            assert r.status_code == 200, r
            stored_cert = r.body.json()[kid]

        assert infra.crypto.are_certs_equal(
            issuer.cert_pem, stored_cert
        ), "input cert is not equal to stored cert"

    return network


def make_attested_cert(network, args):
    keygen = os.path.join(args.binary_dir, "keygenerator.sh")
    oeutil = os.path.join(args.oe_binary, "oeutil")
    infra.proc.ccall(
        keygen, "--name", "attested", "--gen-enc-key", path=network.common_dir
    ).check_returncode()
    privk = os.path.join(network.common_dir, "attested_enc_privk.pem")
    pubk = os.path.join(network.common_dir, "attested_enc_pubk.pem")
    der = os.path.join(network.common_dir, "oe_cert.der")
    infra.proc.ccall(
        oeutil, "generate-evidence", "-f", "cert", privk, pubk, "-o", der
    ).check_returncode()
    pem = os.path.join(network.common_dir, "oe_cert.pem")
    infra.proc.ccall(
        "openssl", "x509", "-inform", "der", "-in", der, "-out", pem
    ).check_returncode()
    return pem


@reqs.description("JWT with SGX key policy")
def test_jwt_with_sgx_key_policy(network, args):
    primary, _ = network.find_nodes()
    oe_cert_path = make_attested_cert(network, args)

    with open(oe_cert_path) as f:
        oe_cert_pem = f.read()

    kid = "my_kid"
    issuer = infra.jwt_issuer.JwtIssuer("my_issuer", oe_cert_pem)

    matching_key_policy = {
        "sgx_claims": {
            "signer_id": "a4922704a099ee48c576cd72f28966fc2e55797a547f658b2c2f9bb426044e15",
            "attributes": "0300000000000000",
        }
    }

    mismatching_key_policy = {
        "sgx_claims": {
            "signer_id": "da9ad7331448980aa28890ce73e433638377f179ab4456b2fe237193193a8d0a",
            "attributes": "0300000000000000",
        }
    }

    LOG.info("Add JWT issuer with SGX key policy")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump(
            {"issuer": issuer.name, "key_policy": matching_key_policy}, metadata_fp
        )
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    LOG.info("Try to add a non-OE-attested cert")
    non_oe_issuer_name = "non_oe_issuer"
    non_oe_issuer = infra.jwt_issuer.JwtIssuer(non_oe_issuer_name)
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(non_oe_issuer.create_jwks(kid), jwks_fp)
        jwks_fp.flush()
        try:
            network.consortium.set_jwt_public_signing_keys(
                primary, non_oe_issuer_name, jwks_fp.name
            )
        except infra.proposal.ProposalNotAccepted:
            pass
        else:
            assert False, "Proposal should not have been created"

    LOG.info("Add an OE-attested cert with matching claims")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(issuer.create_jwks(kid), jwks_fp)
        jwks_fp.flush()
        network.consortium.set_jwt_public_signing_keys(
            primary, issuer.name, jwks_fp.name
        )

    LOG.info("Update JWT issuer with mismatching SGX key policy")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump(
            {
                "issuer": issuer.name,
                "key_policy": mismatching_key_policy,
            },
            metadata_fp,
        )
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    LOG.info("Try to add an OE-attested cert with mismatching claims")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(non_oe_issuer.create_jwks(kid), jwks_fp)
        jwks_fp.flush()
        try:
            network.consortium.set_jwt_public_signing_keys(
                primary, non_oe_issuer_name, jwks_fp.name
            )
        except infra.proposal.ProposalNotAccepted:
            pass
        else:
            assert False, "Proposal should not have been created"

    return network


@reqs.description("JWT with SGX key filter")
def test_jwt_with_sgx_key_filter(network, args):
    primary, _ = network.find_nodes()

    oe_cert_path = make_attested_cert(network, args)
    with open(oe_cert_path) as f:
        oe_cert_pem = f.read()

    oe_issuer = infra.jwt_issuer.JwtIssuer("oe_issuer", oe_cert_pem)
    non_oe_issuer = infra.jwt_issuer.JwtIssuer("non_oe_issuer_name")

    oe_kid = "oe_kid"
    non_oe_kid = "non_oe_kid"

    LOG.info("Add JWT issuer with SGX key filter")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump({"issuer": oe_issuer.name, "key_filter": "sgx"}, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    LOG.info("Add multiple certs (1 SGX, 1 non-SGX)")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        oe_jwks = oe_issuer.create_jwks(oe_kid)
        non_oe_jwks = non_oe_issuer.create_jwks(non_oe_kid)
        jwks = {"keys": non_oe_jwks["keys"] + oe_jwks["keys"]}
        json.dump(jwks, jwks_fp)
        jwks_fp.flush()
        network.consortium.set_jwt_public_signing_keys(
            primary, oe_issuer.name, jwks_fp.name
        )

        with primary.client(network.consortium.get_any_active_member().local_id) as c:
            r = c.get("/gov/jwt_keys/all")
            assert r.status_code == 200, r
            stored_jwt_signing_keys = r.body.json()

        assert non_oe_kid not in stored_jwt_signing_keys, stored_jwt_signing_keys
        assert oe_kid in stored_jwt_signing_keys, stored_jwt_signing_keys

    return network


def check_kv_jwt_key_matches(network, kid, cert_pem):
    primary, _ = network.find_nodes()
    with primary.client(network.consortium.get_any_active_member().local_id) as c:
        r = c.get("/gov/jwt_keys/all")
        assert r.status_code == 200, r
        latest_jwt_signing_keys = r.body.json()

    if cert_pem is None:
        assert kid not in latest_jwt_signing_keys
    else:
        stored_cert = latest_jwt_signing_keys[kid]
        assert infra.crypto.are_certs_equal(
            cert_pem, stored_cert
        ), "input cert is not equal to stored cert"


def get_jwt_refresh_endpoint_metrics(network) -> dict:
    primary, _ = network.find_nodes()
    with primary.client(network.consortium.get_any_active_member().local_id) as c:
        r = c.get("/gov/api/metrics")
        m = next(
            v
            for v in r.body.json()["metrics"]
            if v["path"] == "jwt_keys/refresh" and v["method"] == "POST"
        )
        assert m["errors"] == 0, m["errors"]  # not used in jwt refresh endpoint
        m["successes"] = m["calls"] - m["failures"]
        return m


@reqs.description("JWT with auto_refresh enabled")
def test_jwt_key_auto_refresh(network, args):
    primary, _ = network.find_nodes()

    ca_cert_bundle_name = "jwt"
    kid = "the_kid"
    issuer_host = "localhost"
    issuer_port = 12345

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
                lambda: check_kv_jwt_key_matches(network, kid, issuer.cert_pem),
                timeout=5,
            )

        LOG.info("Check that JWT refresh endpoint has no failures")
        m = get_jwt_refresh_endpoint_metrics(network)
        assert m["failures"] == 0, m["failures"]
        assert m["successes"] > 0, m["successes"]

        LOG.info("Serve invalid JWKS")
        server.jwks = {"foo": "bar"}

        LOG.info("Check that JWT refresh endpoint has some failures")

        def check_has_failures():
            m = get_jwt_refresh_endpoint_metrics(network)
            assert m["failures"] > 0, m["failures"]

        with_timeout(check_has_failures, timeout=5)

    LOG.info("Restart OpenID endpoint server with new keys")
    kid2 = "the_kid_2"
    issuer.refresh_keys()
    with issuer.start_openid_server(issuer_port, kid2):
        LOG.info("Check that keys got refreshed")
        with_timeout(lambda: check_kv_jwt_key_matches(network, kid, None), timeout=5)
        check_kv_jwt_key_matches(network, kid2, issuer.cert_pem)

    return network


@reqs.description("JWT with auto_refresh enabled, initial refresh")
def test_jwt_key_initial_refresh(network, args):
    primary, _ = network.find_nodes()

    ca_cert_bundle_name = "jwt"
    kid = "my_kid"
    issuer_host = "localhost"
    issuer_port = 12345

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
            lambda: check_kv_jwt_key_matches(network, kid, issuer.cert_pem), timeout=5
        )

        LOG.info("Check that JWT refresh endpoint has no failures")
        m = get_jwt_refresh_endpoint_metrics(network)
        assert m["failures"] == 0, m["failures"]
        assert m["successes"] > 0, m["successes"]

    return network


def with_timeout(fn, timeout):
    t0 = time.time()
    while True:
        try:
            return fn()
        except Exception:
            if time.time() - t0 < timeout:
                time.sleep(0.1)
            else:
                raise


def run(args):
    args.jwt_key_refresh_interval_s = 1

    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_jwt_without_key_policy(network, args)
        if args.enclave_type != "virtual":
            network = test_jwt_with_sgx_key_policy(network, args)
            network = test_jwt_with_sgx_key_filter(network, args)
        network = test_jwt_key_auto_refresh(network, args)

        # Check that auto refresh also works on backups
        primary, _ = network.find_primary()
        primary.stop()
        network.wait_for_new_primary(primary)
        network = test_jwt_key_auto_refresh(network, args)

    args.jwt_key_refresh_interval_s = 100000
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_jwt_key_initial_refresh(network, args)

        # Check that initial refresh also works on backups
        primary, _ = network.find_primary()
        primary.stop()
        network.wait_for_new_primary(primary)
        network = test_jwt_key_initial_refresh(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run(args)
