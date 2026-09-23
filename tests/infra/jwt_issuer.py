# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import base64
import json
import os
import shutil
import ssl
import tempfile
import threading
import time
import uuid
from contextlib import AbstractContextManager
from enum import Enum
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_pem_x509_certificate
from loguru import logger as LOG

import infra.crypto
from infra.log_capture import flush_info
from infra.node import CCFVersion


class JwtAlg(Enum):
    RS256 = "RS256"  # RSA using SHA-256
    ES256 = "ES256"  # ECDSA using P-256 and SHA-256


class JwtAuthType(Enum):
    CERT = 1
    KEY = 2


def make_bearer_header(jwt):
    return {"authorization": "Bearer " + jwt}


class MyHTTPRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, openid_server, *args):
        self.openid_server = openid_server
        BaseHTTPRequestHandler.__init__(self, *args)

    def do_GET(self):
        routes = {
            "/.well-known/openid-configuration": self.openid_server.metadata,
            "/keys": self.openid_server.jwks,
        }
        body = routes.get(self.path)
        if body is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = json.dumps(body).encode()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Length", str(len(body)))
        if self.openid_server.inject_oversized_header:
            default_max_header_size = 16 * 1024
            self.send_header(
                "X-OpenID-Provider-Header", "x" * default_max_header_size * 2
            )
        self.end_headers()
        self.wfile.write(body)
        self.openid_server.request_count += 1

    def log_message(self, fmt, *args):
        LOG.trace(f"OpenIDProviderServer: {fmt % args}")


class OpenIDProviderServer(AbstractContextManager):
    def __init__(
        self,
        port: int,
        tls_key_pem: str,
        tls_cert_pem: str,
        jwks: dict,
        host: str = "127.0.0.1",
    ):
        # Default to a concrete IPv4 loopback address rather than "localhost".
        # "localhost" resolves to both 127.0.0.1 and ::1, but this server binds
        # a single address; the mismatch makes libcurl clients (e.g. CCF's JWT
        # key auto-refresh) pay a ~200ms Happy Eyeballs fallback per connection
        # when they try the unused address family first.
        self.host = host
        self.port = port
        self.jwks = jwks
        self.tls_key_pem = tls_key_pem
        self.tls_cert_pem = tls_cert_pem
        self.bind_port = None
        self.start(self.port)
        self.inject_oversized_header = False
        self.request_count = 0

    def start(self, port):
        def handler(*args):
            MyHTTPRequestHandler(self, *args)

        with tempfile.NamedTemporaryFile(
            prefix="ccf", mode="w+"
        ) as keyfile_fp, tempfile.NamedTemporaryFile(
            prefix="ccf", mode="w+"
        ) as certfile_fp:
            keyfile_fp.write(self.tls_key_pem)
            keyfile_fp.flush()
            certfile_fp.write(self.tls_cert_pem)
            certfile_fp.flush()

            self.httpd = HTTPServer((self.host, port), handler)
            context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(
                certfile=certfile_fp.name,
                keyfile=keyfile_fp.name,
            )
            self.httpd.socket = context.wrap_socket(
                self.httpd.socket,
                server_side=True,
            )
            self.thread = threading.Thread(None, self.httpd.serve_forever)
            self.thread.setDaemon(True)
            self.bind_port = self.httpd.socket.getsockname()[1]
            self.metadata = {"jwks_uri": f"https://{self.host}:{self.bind_port}/keys"}
            self.thread.start()
            LOG.info(
                f"OpenIDProviderServer https://{self.host}:{self.bind_port} started"
            )

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()
        LOG.info("OpenIdProviderServer stopped")

    def set_jwks(self, jwks):
        self.jwks = jwks

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()


def get_jwt_issuers(args, node):
    with node.api_versioned_client(api_version=args.gov_api_version) as c:
        r = c.get("/gov/service/jwk")
        assert r.status_code == HTTPStatus.OK, r
        body = r.body.json()
        return body["issuers"]


def get_jwt_keys(args, node):
    with node.api_versioned_client(api_version=args.gov_api_version) as c:
        r = c.get("/gov/service/jwk")
        assert r.status_code == HTTPStatus.OK, r
        body = r.body.json()
        return body["keys"]


def to_b64(number: int, size=None):
    as_bytes = number.to_bytes(size or (number.bit_length() + 7) // 8, "big")
    # JWK numeric fields use unpadded base64url (RFC 7518 section 6 referencing
    # RFC 4648 section 5).
    return base64.urlsafe_b64encode(as_bytes).rstrip(b"=").decode("ascii")


def system_ca_bundle():
    paths = ssl.get_default_verify_paths()
    for candidate in (paths.cafile, paths.openssl_cafile):
        if candidate and os.path.isfile(candidate):
            return candidate
    raise RuntimeError("Could not locate the system CA bundle")


class NodeTrustStore(AbstractContextManager):
    """
    PEM bundle passed to nodes via SSL_CERT_FILE, so that their outbound TLS
    connections trust the self-signed certificates of test OpenID servers.
    It starts from the system roots, since SSL_CERT_FILE replaces the system
    CA bundle, and issuers are appended as they are created.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._file = tempfile.NamedTemporaryFile(  # noqa: SIM115 - closed in __exit__
            prefix="ccf_trust_store_", mode="w+"
        )
        with open(system_ca_bundle(), encoding="utf-8") as system_roots:
            shutil.copyfileobj(system_roots, self._file)
        self._file.write("\n")
        self._file.flush()

    def __exit__(self, *exc_info):
        self._file.close()

    @property
    def path(self):
        return self._file.name

    @property
    def env(self):
        return {"SSL_CERT_FILE": self.path}

    def trust(self, issuer):
        with self._lock:
            self._file.write(issuer.tls_cert)
            self._file.write("\n")
            self._file.flush()


class JwtIssuer:
    TEST_JWT_ISSUER_NAME = "https://example.issuer"
    TEST_CA_BUNDLE_NAME = "test_ca_bundle_name"
    # Releases up to and including this one only auto-refresh keys over TLS
    # connections verified against a governance-managed CA bundle, which their
    # constitutions require set_jwt_issuer to name. Later versions verify
    # against the node's trust store instead (see NodeTrustStore).
    LAST_RELEASE_WITH_GOVERNANCE_CA_BUNDLES = "ccf-7.0.16"

    def _generate_auth_data(self, cn=None):
        if self._alg == JwtAlg.RS256:
            key_priv, key_pub = infra.crypto.generate_rsa_keypair(2048)
        elif self._alg == JwtAlg.ES256:
            key_priv, key_pub = infra.crypto.generate_ec_keypair(ec.SECP256R1)
        else:
            raise ValueError(f"Unsupported algorithm: {self._alg}")

        cert = infra.crypto.generate_cert(key_priv, cn=cn, ca=True, san=cn)
        return (key_priv, key_pub), cert

    def __init__(
        self,
        name=TEST_JWT_ISSUER_NAME,
        cert=None,
        refresh_interval=3,
        cn=None,
        auth_type=JwtAuthType.CERT,
        alg=JwtAlg.RS256,
    ):
        self.name = name
        self.default_kid = f"{uuid.uuid4()}"
        self.server = None
        self.refresh_interval = refresh_interval
        # Auto-refresh ON if issuer name starts with "https://"
        self.auto_refresh = self.name.startswith("https://")
        stripped_host = self.name[len("https://") :] if self.auto_refresh else None
        self._auth_type = auth_type
        self._alg = alg
        # The effective host this issuer's TLS cert is valid for. The OpenID
        # provider server (see start_openid_server) binds and advertises this
        # same host so that the address CCF's curl client connects to matches
        # both the cert SAN and a single, concrete loopback address.
        self.host = cn or stripped_host or name
        (self.tls_priv, _), self.tls_cert = self._generate_auth_data(
            cn or stripped_host or name
        )
        if not cert:
            self.refresh_keys()
        else:
            self.cert_pem = cert

    @property
    def public_key(self):
        cert = load_pem_x509_certificate(self.cert_pem.encode(), default_backend())
        return cert.public_key()

    @property
    def issuer_url(self):
        name = f"{self.name}"
        if self.server:
            name += f":{self.server.bind_port}"
        return name

    def refresh_keys(self, kid=None, send_update=True):
        if not kid:
            self.default_kid = f"{uuid.uuid4()}"
        kid_ = kid or self.default_kid
        (self.key_priv_pem, self.key_pub_pem), self.cert_pem = (
            self._generate_auth_data()
        )
        if self.server and send_update:
            self.server.set_jwks(self.create_jwks(kid_))

    def _create_jwks_with_cert(self, kid):
        der_b64 = base64.b64encode(infra.crypto.cert_pem_to_der(self.cert_pem)).decode(
            "ascii"
        )
        return {"kty": "RSA", "kid": kid, "x5c": [der_b64], "issuer": self.name[::]}

    def _create_jwks_with_raw_key(self, kid):
        pubkey = self.public_key
        if self._alg == JwtAlg.RS256:
            n = to_b64(pubkey.public_numbers().n)
            e = to_b64(pubkey.public_numbers().e)
            return {"kty": "RSA", "kid": kid, "n": n, "e": e, "issuer": self.name[::]}
        elif self._alg == JwtAlg.ES256:
            x = to_b64(pubkey.public_numbers().x, 32)
            y = to_b64(pubkey.public_numbers().y, 32)
            return {
                "kty": "EC",
                "kid": kid,
                "x": x,
                "y": y,
                "crv": "P-256",
                "issuer": self.name,
            }
        else:
            raise ValueError(f"Unsupported algorithm: {self._alg}")

    def _create_jwks(self, kid):
        if self._auth_type == JwtAuthType.KEY:
            return self._create_jwks_with_raw_key(kid)
        elif self._auth_type == JwtAuthType.CERT:
            return self._create_jwks_with_cert(kid)
        else:
            raise ValueError(f"Unsupported auth type: {self._auth_type}")

    def create_jwks(self, kid=None):
        kid_ = kid or self.default_kid
        return {"keys": [self._create_jwks(kid_)]}

    def create_jwks_for_kids(self, kids):
        jwks = {}
        jwks["keys"] = []
        for kid in kids:
            jwks["keys"].append(self._create_jwks(kid))
        return jwks

    def register(self, network, kid=None):
        kid_ = kid or self.default_kid
        primary, _ = network.find_primary()

        issuer = {"issuer": self.issuer_url, "auto_refresh": self.auto_refresh}
        if self.auto_refresh and not primary.version_after(
            self.LAST_RELEASE_WITH_GOVERNANCE_CA_BUNDLES
        ):
            with tempfile.NamedTemporaryFile(
                prefix="ccf", mode="w+"
            ) as ca_cert_bundle_fp:
                ca_cert_bundle_fp.write(self.tls_cert)
                ca_cert_bundle_fp.flush()
                network.consortium.set_ca_cert_bundle(
                    primary, self.TEST_CA_BUNDLE_NAME, ca_cert_bundle_fp.name
                )
            issuer["ca_cert_bundle_name"] = self.TEST_CA_BUNDLE_NAME

        with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
            json.dump(issuer, metadata_fp)
            metadata_fp.flush()
            network.consortium.set_jwt_issuer(primary, metadata_fp.name)

        with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
            json.dump(self.create_jwks(kid_), jwks_fp)
            jwks_fp.flush()
            network.consortium.set_jwt_public_signing_keys(
                primary, self.issuer_url, jwks_fp.name
            )

    def start_openid_server(self, port=0, kid=None):
        kid_ = kid or self.default_kid
        self.server = OpenIDProviderServer(
            port, self.tls_priv, self.tls_cert, self.create_jwks(kid_), host=self.host
        )
        return self.server

    def issue_jwt(self, kid=None, claims=None):
        claims = claims or {}
        kid_ = kid or self.default_kid
        # JWT formats times as NumericDate, which is a JSON numeric value counting seconds since the epoch
        now = int(time.time())
        if "nbf" not in claims:
            # Insert default Not Before claim, valid from ~10 seconds ago
            claims["nbf"] = now - 10
        if "exp" not in claims:
            # Insert default Expiration Time claim, valid for ~1hr
            claims["exp"] = now + 3600
        if "iss" not in claims:
            claims["iss"] = self.name

        return infra.crypto.create_jwt(claims, self.key_priv_pem, kid_, self._alg.value)

    def wait_for_refresh(self, network, args, kid=None):
        timeout = self.refresh_interval * 3
        kid_ = kid or self.default_kid
        primary, _ = network.find_nodes()
        end_time = time.time() + timeout
        if CCFVersion(primary.version) > CCFVersion("ccf-5.0.0-rc3"):
            with primary.api_versioned_client(
                network.consortium.get_any_active_member().local_id,
                api_version=args.gov_api_version,
            ) as c:
                while time.time() < end_time:
                    logs = []
                    r = c.get("/gov/service/jwk", log_capture=logs)
                    assert r.status_code == 200, r
                    body = r.body.json()
                    LOG.warning(body)
                    keys = body["keys"]
                    if kid_ in keys:
                        if "publicKey" in keys[kid_][0]:
                            stored_key = keys[kid_][0]["publicKey"]
                            if self.key_pub_pem == stored_key:
                                flush_info(logs)
                                return
                        else:
                            stored_cert = keys[kid_][0]["certificate"]
                            if self.cert_pem == stored_cert:
                                flush_info(logs)
                                return
                    time.sleep(0.1)
        else:
            with primary.client(
                network.consortium.get_any_active_member().local_id
            ) as c:
                while time.time() < end_time:
                    logs = []
                    r = c.get("/gov/jwt_keys/all", log_capture=logs)
                    assert r.status_code == 200, r
                    keys = r.body.json()
                    if kid_ in keys:
                        kid_vals = keys[kid_]
                        if CCFVersion(primary.version) > CCFVersion("ccf-5.0.0-dev17"):
                            assert len(kid_vals) == 1
                            stored_cert = kid_vals[0]["cert"]
                        else:
                            stored_cert = kid_vals["cert"]
                        if self.cert_pem == stored_cert:
                            flush_info(logs)
                            return
                    time.sleep(0.1)
        flush_info(logs)
        raise TimeoutError(
            f"JWT public signing keys were not refreshed after {timeout}s"
        )
