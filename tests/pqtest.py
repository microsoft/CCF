# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""
curl handshakes with a TLS server presenting the ML-DSA certificates CCF's
PKI issues for a network: a node certificate endorsed by a self-signed
service identity, both issued by the pqtest binary.
"""

import contextlib
import http.server
import re
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

# pqtest issues the node certificate for this address
HOST = "127.0.0.1"
PARAMETER_SETS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
BODY = b"ML-DSA over TLS 1.3\n"

# curl -v: "SSL connection using TLSv1.3 / <cipher> / <group> / <sigalg>"
SSL_CONNECTION = re.compile(r"SSL connection using TLSv1.3 / (\S+) / (\S+) / (\S+)")
# curl -v: "Certificate level 0: Public key type ML-DSA-65 (...), signed using ML-DSA-65"
CERTIFICATE_LEVEL = re.compile(
    r"Certificate level (\d+): Public key type (\S+) .*, signed using (\S+)"
)

# curl exit codes
CURLE_SSL_CONNECT_ERROR = 35
CURLE_PEER_FAILED_VERIFICATION = 60


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        # Without a length, curl reads to EOF and rejects the close as truncation
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, fmt, *args):
        pass


def issue(pqtest, parameter_set, out_dir):
    """Returns the paths of the service certificate, node certificate and node key"""
    out_dir.mkdir()
    subprocess.run([pqtest, parameter_set, out_dir], check=True)
    return [
        out_dir / n for n in ("service_cert.pem", "node_cert.pem", "node_privk.pem")
    ]


def corrupt_signature(cert, out):
    """Copies cert to out with one bit of its signature, the last DER field, flipped"""
    der = bytearray(ssl.PEM_cert_to_DER_cert(cert.read_text()))
    der[-1] ^= 0x01
    out.write_text(ssl.DER_cert_to_PEM_cert(bytes(der)))
    return out


@contextlib.contextmanager
def serve(node_cert, node_key):
    """HTTPS server on an ephemeral port, authenticating with the node certificate"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(node_cert, node_key)
    with http.server.ThreadingHTTPServer((HOST, 0), Handler) as httpd:
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"https://{HOST}:{httpd.server_address[1]}/"
        finally:
            httpd.shutdown()
            thread.join()


def curl(url, *options):
    return subprocess.run(
        ["curl", "--silent", "--show-error", "--verbose", *options, url],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def expect(condition, completed, what):
    if not condition:
        print(completed.stderr, file=sys.stderr)
        raise AssertionError(f"{what} (curl exit code {completed.returncode})")


def expect_rejected(what, exit_codes, url, *options):
    completed = curl(url, *options)
    expect(completed.returncode in exit_codes, completed, what)
    return completed


def require_curl_sigalgs():
    """Fails unless curl has --sigalgs, which the classical-only client needs"""
    version = subprocess.check_output(["curl", "--version"], text=True).splitlines()[0]
    options = subprocess.check_output(["curl", "--help", "all"], text=True)
    assert "--sigalgs" in options, f"{version} has no --sigalgs option (curl 8.14+)"


def test_parameter_set(pqtest, parameter_set):
    with tempfile.TemporaryDirectory() as tmp:
        service_cert, node_cert, node_key = issue(
            pqtest, parameter_set, Path(tmp, "network")
        )
        other_service_cert, _, _ = issue(pqtest, parameter_set, Path(tmp, "other"))

        with serve(node_cert, node_key) as url:
            # The service identity authenticates the node, with ML-DSA at every
            # layer: the node certificate's signature and the TLS 1.3
            # CertificateVerify, whose algorithm curl names by OID
            completed = curl(url, "--cacert", service_cert)
            expect(completed.returncode == 0, completed, "handshake failed")
            expect(completed.stdout == BODY.decode(), completed, "unexpected body")
            match = SSL_CONNECTION.search(completed.stderr)
            expect(match is not None, completed, "no TLS 1.3 connection line")
            cipher, group, sigalg = match.groups()
            expect(
                sigalg == f"id-{parameter_set.lower()}",
                completed,
                f"unexpected signature algorithm {sigalg}",
            )
            # Node certificate at level 0, service identity at level 1, both
            # ML-DSA keys signed with ML-DSA
            levels = CERTIFICATE_LEVEL.findall(completed.stderr)
            expected = [(str(level), parameter_set, parameter_set) for level in (0, 1)]
            expect(
                levels == expected, completed, f"unexpected certificate chain {levels}"
            )
            print(f"{parameter_set}: TLSv1.3 / {cipher} / {group} / {sigalg}")

            # The node is not trusted without the service identity, nor under
            # another service's identity
            expect_rejected(
                "accepted without a trust anchor", {CURLE_PEER_FAILED_VERIFICATION}, url
            )
            expect_rejected(
                "accepted under another service identity",
                {CURLE_PEER_FAILED_VERIFICATION},
                url,
                "--cacert",
                other_service_cert,
            )
            # A client offering only classical signature algorithms cannot
            # complete the handshake
            expect_rejected(
                "handshake completed without ML-DSA signature algorithms",
                {CURLE_SSL_CONNECT_ERROR},
                url,
                "--cacert",
                service_cert,
                "--sigalgs",
                "ecdsa_secp384r1_sha384",
            )

        # A node certificate whose ML-DSA signature is corrupted is rejected,
        # so the signature is verified rather than the issuer merely matched.
        # OpenSSL reports the failure through its error queue, which curl may
        # surface as a connect error instead of a peer verification failure.
        corrupted = corrupt_signature(node_cert, Path(tmp, "corrupted.pem"))
        with serve(corrupted, node_key) as url:
            completed = expect_rejected(
                "accepted a corrupted node certificate signature",
                {CURLE_SSL_CONNECT_ERROR, CURLE_PEER_FAILED_VERIFICATION},
                url,
                "--cacert",
                service_cert,
            )
            expect(
                "signature failure" in completed.stderr,
                completed,
                "rejected for another reason",
            )


def run(pqtest):
    require_curl_sigalgs()
    for parameter_set in PARAMETER_SETS:
        test_parameter_set(pqtest, parameter_set)


if __name__ == "__main__":
    run(sys.argv[1])
