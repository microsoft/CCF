import os
import tempfile
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from http import HTTPStatus
import ssl
import threading
from contextlib import AbstractContextManager
import infra.crypto

class OpenIDProviderServer(AbstractContextManager):
    def __init__(self, port: int, tls_key_pem: str, tls_cert_pem: str, jwks: dict):
        host = "localhost"
        metadata = {"jwks_uri": f"https://{host}:{port}/keys"}
        routes = {"/.well-known/openid-configuration": metadata, "/keys": jwks}

        class MyHTTPRequestHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = routes.get(self.path)
                if body is None:
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                print("OpenID provider server: {}", self.path)
                self.send_response(HTTPStatus.OK)
                b = json.dumps(body).encode()
                self.send_header('Content-Length', str(len(b)))
                self.end_headers()
                self.wfile.write(b)

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

def main():
    port = 8860
    jwks = {"foo": "bar"}

    key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
    cert_pem = infra.crypto.generate_cert(key_priv_pem, "localhost")

    with open('server_test_cert.pem', 'w') as f:
        f.write(cert_pem)

    OpenIDProviderServer(port, key_priv_pem, cert_pem, jwks)

if __name__ == '__main__':
    main()
