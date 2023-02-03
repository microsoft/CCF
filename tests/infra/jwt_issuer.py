# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.crypto
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from http import HTTPStatus
import ssl
import threading
from contextlib import AbstractContextManager
import tempfile
import json
import time
from infra.log_capture import flush_info
from jwt_test import extract_b64
from loguru import logger as LOG

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
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # pylint: disable=arguments-differ
        LOG.trace(f"OpenIDProviderServer: {fmt % args}")


class OpenIDProviderServer(AbstractContextManager):
    def __init__(self, port: int, tls_key_pem: str, tls_cert_pem: str, jwks: dict):
        self.host = "localhost"
        self.port = port
        self.jwks = jwks
        self.tls_key_pem = tls_key_pem
        self.tls_cert_pem = tls_cert_pem
        self.bind_port = None
        self.start(self.port)

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


class JwtIssuer:
    TEST_JWT_ISSUER_NAME = "test_jwt_issuer"
    TEST_JWT_KID = "test_jwt_kid"
    TEST_CA_BUNDLE_NAME = "test_ca_bundle_name"

    def _generate_cert(self, cn=None):
        key_priv, key_pub = infra.crypto.generate_rsa_keypair(2048)
        cert = infra.crypto.generate_cert(key_priv, cn=cn)
        return (key_priv, key_pub), cert

    def __init__(
        self, name=TEST_JWT_ISSUER_NAME, cert=None, refresh_interval=3, cn=None
    ):
        self.name = name
        self.server = None
        self.refresh_interval = refresh_interval
        # Auto-refresh ON if issuer name starts with "https://"
        self.auto_refresh = self.name.startswith("https://")
        stripped_host = self.name[len("https://") :] if self.auto_refresh else None
        (self.tls_priv, _), self.tls_cert = self._generate_cert(
            cn or stripped_host or name
        )
        if not cert:
            self.refresh_keys()
        else:
            self.cert_pem = cert

    def refresh_keys(self, kid=TEST_JWT_KID):
        (self.key_priv_pem, self.key_pub_pem), self.cert_pem = self._generate_cert()
        if self.server:
            self.server.set_jwks(self.create_jwks(kid))

    def _create_jwks(self, kid, test_invalid_is_key=False):
        der_b64 = base64.b64encode(
            infra.crypto.cert_pem_to_der(self.cert_pem)
            if not test_invalid_is_key
            else infra.crypto.pub_key_pem_to_der(self.key_pub_pem)
        ).decode("ascii")
        return {"kty": "RSA", "kid": kid, "x5c": [der_b64]}

    def create_jwks(self, kid=TEST_JWT_KID, test_invalid_is_key=False):
        return {"keys": [self._create_jwks(kid, test_invalid_is_key)]}

    def create_jwks_for_kids(self, kids):
        jwks = {}
        jwks["keys"] = []
        for kid in kids:
            jwks["keys"].append(self._create_jwks(kid))
        return jwks

    def register(self, network, kid=TEST_JWT_KID, ca_bundle_name=TEST_CA_BUNDLE_NAME):
        primary, _ = network.find_primary()

        if self.auto_refresh:
            with tempfile.NamedTemporaryFile(
                prefix="ccf", mode="w+"
            ) as ca_cert_bundle_fp:
                ca_cert_bundle_fp.write(self.tls_cert)
                ca_cert_bundle_fp.flush()
                network.consortium.set_ca_cert_bundle(
                    primary, ca_bundle_name, ca_cert_bundle_fp.name
                )

        full_name = f"{self.name}:{self.server.bind_port}" if self.server else self.name
        with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
            issuer = {"issuer": full_name, "auto_refresh": self.auto_refresh}
            if self.auto_refresh:
                issuer.update({"ca_cert_bundle_name": ca_bundle_name})
            json.dump(issuer, metadata_fp)
            metadata_fp.flush()
            network.consortium.set_jwt_issuer(primary, metadata_fp.name)

        with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as jwks_fp:
            json.dump(self.create_jwks(kid), jwks_fp)
            jwks_fp.flush()
            network.consortium.set_jwt_public_signing_keys(
                primary, full_name, jwks_fp.name
            )

    def start_openid_server(self, port=0, kid=TEST_JWT_KID):
        self.server = OpenIDProviderServer(
            port, self.tls_priv, self.tls_cert, self.create_jwks(kid)
        )
        return self.server

    def issue_jwt(self, kid=TEST_JWT_KID, claims=None):
        claims = claims or {}
        # JWT formats times as NumericDate, which is a JSON numeric value counting seconds sine the epoch
        now = int(time.time())
        if "nbf" not in claims:
            # Insert default Not Before claim, valid from ~10 seconds ago
            claims["nbf"] = now - 10
        if "exp" not in claims:
            # Insert default Expiration Time claim, valid for ~1hr
            claims["exp"] = now + 3600
        return infra.crypto.create_jwt(claims, self.key_priv_pem, kid)

    def wait_for_refresh(self, network, kid=TEST_JWT_KID):
        timeout = self.refresh_interval * 3
        LOG.info(f"Waiting {timeout}s for JWT key refresh")
        primary, _ = network.find_nodes()
        end_time = time.time() + timeout
        with primary.client(network.consortium.get_any_active_member().local_id) as c:
            while time.time() < end_time:
                logs = []
                r = c.get("/gov/kv/jwt/public_signing_keys", log_capture=logs)
                assert r.status_code == 200, r
                stored_cert = r.body.json()[kid]
                if extract_b64(self.cert_pem) == stored_cert:
                    flush_info(logs)
                    return
                time.sleep(0.1)
        flush_info(logs)
        raise TimeoutError(
            f"JWT public signing keys were not refreshed after {timeout}s"
        )
