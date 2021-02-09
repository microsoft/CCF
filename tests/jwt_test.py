# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import tempfile
import json
import time
import base64
import http
from http.server import HTTPServer, BaseHTTPRequestHandler
from http import HTTPStatus
import ssl
import threading
from contextlib import AbstractContextManager
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs

from loguru import logger as LOG

this_dir = os.path.dirname(__file__)


def create_jwks(kid, cert_pem, test_invalid_is_key=False):
    der_b64 = base64.b64encode(
        infra.crypto.cert_pem_to_der(cert_pem)
        if not test_invalid_is_key
        else infra.crypto.pub_key_pem_to_der(cert_pem)
    ).decode("ascii")
    return {"keys": [{"kty": "RSA", "kid": kid, "x5c": [der_b64]}]}


@reqs.description("JWT without key policy")
def test_jwt_without_key_policy(network, args):
    primary, _ = network.find_nodes()

    key_priv_pem, key_pub_pem = infra.crypto.generate_rsa_keypair(2048)
    cert_pem = infra.crypto.generate_cert(key_priv_pem)
    kid = "my_kid"
    issuer = "my_issuer"

    LOG.info("Try to add JWT signing key without matching issuer")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(create_jwks(kid, cert_pem), jwks_fp)
        jwks_fp.flush()
        try:
            network.consortium.set_jwt_public_signing_keys(
                primary, issuer, jwks_fp.name
            )
        except infra.proposal.ProposalNotAccepted:
            pass
        else:
            assert False, "Proposal should not have been created"

    LOG.info("Add JWT issuer")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump({"issuer": issuer}, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    LOG.info("Try to add a public key instead of a certificate")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(create_jwks(kid, key_pub_pem, test_invalid_is_key=True), jwks_fp)
        jwks_fp.flush()
        try:
            network.consortium.set_jwt_public_signing_keys(
                primary, issuer, jwks_fp.name
            )
        except infra.proposal.ProposalNotAccepted:
            pass
        else:
            assert False, "Proposal should not have been created"

    LOG.info("Add JWT signing key with matching issuer")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(create_jwks(kid, cert_pem), jwks_fp)
        jwks_fp.flush()
        network.consortium.set_jwt_public_signing_keys(primary, issuer, jwks_fp.name)

    LOG.info("Check if JWT signing key was stored correctly")
    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post(
            "/gov/read", {"table": "public:ccf.gov.jwt.public_signing_keys", "key": kid}
        )
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        # Note that /gov/read returns all data as JSON.
        # Here, the stored data is a uint8 array, therefore it
        # is returned as an array of integers.
        cert_kv_der = bytes(r.body.json())
        cert_kv_pem = infra.crypto.cert_der_to_pem(cert_kv_der)
        assert infra.crypto.are_certs_equal(
            cert_pem, cert_kv_pem
        ), "stored cert not equal to input cert"

    LOG.info("Remove JWT issuer")
    network.consortium.remove_jwt_issuer(primary, issuer)

    LOG.info("Check if JWT signing key was deleted")
    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post(
            "/gov/read", {"table": "public:ccf.gov.jwt.public_signing_keys", "key": kid}
        )
        assert r.status_code == http.HTTPStatus.NOT_FOUND.value, r.status_code

    LOG.info("Add JWT issuer with initial keys")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump({"issuer": issuer, "jwks": create_jwks(kid, cert_pem)}, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    LOG.info("Check if JWT signing key was stored correctly")
    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post(
            "/gov/read", {"table": "public:ccf.gov.jwt.public_signing_keys", "key": kid}
        )
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code
        cert_kv_der = bytes(r.body.json())
        cert_kv_pem = infra.crypto.cert_der_to_pem(cert_kv_der)
        assert infra.crypto.are_certs_equal(
            cert_pem, cert_kv_pem
        ), "stored cert not equal to input cert"

    return network


@reqs.description("JWT with SGX key policy")
def test_jwt_with_sgx_key_policy(network, args):
    primary, _ = network.find_nodes()

    oe_cert_path = os.path.join(this_dir, "oe_cert.pem")
    with open(oe_cert_path) as f:
        oe_cert_pem = f.read()

    kid = "my_kid"
    issuer = "my_issuer"

    matching_key_policy = {
        "sgx_claims": {
            "signer_id": "ca9ad7331448980aa28890ce73e433638377f179ab4456b2fe237193193a8d0a",
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
        json.dump({"issuer": issuer, "key_policy": matching_key_policy}, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    LOG.info("Try to add a non-OE-attested cert")
    key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
    non_oe_cert_pem = infra.crypto.generate_cert(key_priv_pem)
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(create_jwks(kid, non_oe_cert_pem), jwks_fp)
        jwks_fp.flush()
        try:
            network.consortium.set_jwt_public_signing_keys(
                primary, issuer, jwks_fp.name
            )
        except infra.proposal.ProposalNotAccepted:
            pass
        else:
            assert False, "Proposal should not have been created"

    LOG.info("Add an OE-attested cert with matching claims")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(create_jwks(kid, oe_cert_pem), jwks_fp)
        jwks_fp.flush()
        network.consortium.set_jwt_public_signing_keys(primary, issuer, jwks_fp.name)

    LOG.info("Update JWT issuer with mismatching SGX key policy")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump(
            {
                "issuer": issuer,
                "key_policy": mismatching_key_policy,
            },
            metadata_fp,
        )
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    LOG.info("Try to add an OE-attested cert with mismatching claims")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        json.dump(create_jwks(kid, non_oe_cert_pem), jwks_fp)
        jwks_fp.flush()
        try:
            network.consortium.set_jwt_public_signing_keys(
                primary, issuer, jwks_fp.name
            )
        except infra.proposal.ProposalNotAccepted:
            pass
        else:
            assert False, "Proposal should not have been created"

    return network


@reqs.description("JWT with SGX key filter")
def test_jwt_with_sgx_key_filter(network, args):
    primary, _ = network.find_nodes()

    oe_cert_path = os.path.join(this_dir, "oe_cert.pem")
    with open(oe_cert_path) as f:
        oe_cert_pem = f.read()
    oe_kid = "oe_kid"

    key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
    non_oe_cert_pem = infra.crypto.generate_cert(key_priv_pem)
    non_oe_kid = "non_oe_kid"

    issuer = "my_issuer"

    LOG.info("Add JWT issuer with SGX key filter")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        json.dump({"issuer": issuer, "key_filter": "sgx"}, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    LOG.info("Add multiple certs (1 SGX, 1 non-SGX)")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
        oe_jwks = create_jwks(oe_kid, oe_cert_pem)
        non_oe_jwks = create_jwks(non_oe_kid, non_oe_cert_pem)
        jwks = {"keys": non_oe_jwks["keys"] + oe_jwks["keys"]}
        json.dump(jwks, jwks_fp)
        jwks_fp.flush()
        network.consortium.set_jwt_public_signing_keys(primary, issuer, jwks_fp.name)

    LOG.info("Check that only SGX cert was added")
    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post(
            "/gov/read",
            {"table": "public:ccf.gov.jwt.public_signing_keys", "key": non_oe_kid},
        )
        assert r.status_code == http.HTTPStatus.NOT_FOUND.value, r.status_code
        r = c.post(
            "/gov/read",
            {"table": "public:ccf.gov.jwt.public_signing_keys", "key": oe_kid},
        )
        assert r.status_code == http.HTTPStatus.OK.value, r.status_code

    return network


class OpenIDProviderServer(AbstractContextManager):
    def __init__(self, port: int, tls_key_pem: str, tls_cert_pem: str, jwks: dict):
        host = "localhost"
        metadata = {"jwks_uri": f"https://{host}:{port}/keys"}
        self.jwks = jwks
        self_ = self

        class MyHTTPRequestHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                routes = {
                    "/.well-known/openid-configuration": metadata,
                    "/keys": self_.jwks,
                }
                body = routes.get(self.path)
                if body is None:
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                body = json.dumps(body).encode()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):  # pylint: disable=arguments-differ
                LOG.debug(f"OpenIDProviderServer: {fmt % args}")

        with tempfile.NamedTemporaryFile(
            prefix="ccf", mode="w+"
        ) as keyfile_fp, tempfile.NamedTemporaryFile(
            prefix="ccf", mode="w+"
        ) as certfile_fp:
            keyfile_fp.write(tls_key_pem)
            keyfile_fp.flush()
            certfile_fp.write(tls_cert_pem)
            certfile_fp.flush()

            self.httpd = HTTPServer((host, port), MyHTTPRequestHandler)
            self.httpd.socket = ssl.wrap_socket(
                self.httpd.socket,
                keyfile=keyfile_fp.name,
                certfile=certfile_fp.name,
                server_side=True,
            )
            self.thread = threading.Thread(None, self.httpd.serve_forever)
            self.thread.start()

    def __exit__(self, exc_type, exc_value, traceback):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()


def check_kv_jwt_key_matches(network, kid, cert_pem):
    primary, _ = network.find_nodes()
    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
        r = c.post(
            "/gov/read",
            {"table": "public:ccf.gov.jwt.public_signing_keys", "key": kid},
        )
        if cert_pem is None:
            assert r.status_code == http.HTTPStatus.NOT_FOUND.value, r.status_code
        else:
            assert r.status_code == http.HTTPStatus.OK.value, r.status_code
            # Note that /gov/read returns all data as JSON.
            # Here, the stored data is a uint8 array, therefore it
            # is returned as an array of integers.
            cert_kv_der = bytes(r.body.json())
            cert_kv_pem = infra.crypto.cert_der_to_pem(cert_kv_der)
            assert infra.crypto.are_certs_equal(
                cert_pem, cert_kv_pem
            ), "stored cert not equal to input cert"


def get_jwt_refresh_endpoint_metrics(network) -> dict:
    primary, _ = network.find_nodes()
    with primary.client(
        f"member{network.consortium.get_any_active_member().member_id}"
    ) as c:
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

    ca_cert_name = "jwt"
    kid = "my_kid"
    issuer_host = "localhost"
    issuer_port = 12345
    issuer = f"https://{issuer_host}:{issuer_port}"

    key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
    cert_pem = infra.crypto.generate_cert(key_priv_pem, cn=issuer_host)

    LOG.info("Add CA cert for JWT issuer")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as ca_cert_fp:
        ca_cert_fp.write(cert_pem)
        ca_cert_fp.flush()
        network.consortium.set_ca_cert(primary, ca_cert_name, ca_cert_fp.name)

    LOG.info("Start OpenID endpoint server")
    jwks = create_jwks(kid, cert_pem)
    with OpenIDProviderServer(issuer_port, key_priv_pem, cert_pem, jwks) as server:
        LOG.info("Add JWT issuer with auto-refresh")
        with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
            json.dump(
                {"issuer": issuer, "auto_refresh": True, "ca_cert_name": ca_cert_name},
                metadata_fp,
            )
            metadata_fp.flush()
            network.consortium.set_jwt_issuer(primary, metadata_fp.name)

        LOG.info("Check that keys got refreshed")
        # Note: refresh interval is set to 1s, see network args below.
        with_timeout(
            lambda: check_kv_jwt_key_matches(network, kid, cert_pem), timeout=5
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
    kid2 = "my_kid_2"
    key2_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
    cert2_pem = infra.crypto.generate_cert(key2_priv_pem, cn=issuer_host)
    jwks = create_jwks(kid2, cert2_pem)
    with OpenIDProviderServer(issuer_port, key_priv_pem, cert_pem, jwks):
        LOG.info("Check that keys got refreshed")
        with_timeout(lambda: check_kv_jwt_key_matches(network, kid, None), timeout=5)
        check_kv_jwt_key_matches(network, kid2, cert2_pem)


@reqs.description("JWT with auto_refresh enabled, initial refresh")
def test_jwt_key_initial_refresh(network, args):
    primary, _ = network.find_nodes()

    ca_cert_name = "jwt"
    kid = "my_kid"
    issuer_host = "localhost"
    issuer_port = 12345
    issuer = f"https://{issuer_host}:{issuer_port}"

    key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
    cert_pem = infra.crypto.generate_cert(key_priv_pem, cn=issuer_host)

    LOG.info("Add CA cert for JWT issuer")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as ca_cert_fp:
        ca_cert_fp.write(cert_pem)
        ca_cert_fp.flush()
        network.consortium.set_ca_cert(primary, ca_cert_name, ca_cert_fp.name)

    LOG.info("Start OpenID endpoint server")
    jwks = create_jwks(kid, cert_pem)
    with OpenIDProviderServer(issuer_port, key_priv_pem, cert_pem, jwks):
        LOG.info("Add JWT issuer with auto-refresh")
        with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
            json.dump(
                {"issuer": issuer, "auto_refresh": True, "ca_cert_name": ca_cert_name},
                metadata_fp,
            )
            metadata_fp.flush()
            network.consortium.set_jwt_issuer(primary, metadata_fp.name)

        LOG.info("Check that keys got refreshed")
        # Auto-refresh interval is set to a large value so that it doesn't happen within the timeout.
        # This is testing the one-off refresh after adding a new issuer.
        with_timeout(
            lambda: check_kv_jwt_key_matches(network, kid, cert_pem), timeout=5
        )

        LOG.info("Check that JWT refresh endpoint has no failures")
        m = get_jwt_refresh_endpoint_metrics(network)
        assert m["failures"] == 0, m["failures"]
        assert m["successes"] > 0, m["successes"]


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
        network = test_jwt_with_sgx_key_policy(network, args)
        network = test_jwt_with_sgx_key_filter(network, args)
        network = test_jwt_key_auto_refresh(network, args)

    args.jwt_key_refresh_interval_s = 100000
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_jwt_key_initial_refresh(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "liblogging"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    run(args)
