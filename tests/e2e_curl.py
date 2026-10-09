# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import asyncio
import os
import random
import re
import ssl
import sys
import tempfile
from datetime import UTC, datetime, timedelta

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


async def echo_handler(request):
    # Extract headers as list of [name, value] pairs
    headers = [[name, value] for name, value in request.headers.items()]

    # Read body
    body = await request.text()

    time_received = datetime.now(UTC)

    # Add random delay between 0 and 10 millisecond
    delay = random.random() / 100
    await asyncio.sleep(delay)

    # Build response data
    response_data = {
        "headers": headers,
        "body": body,
        "metadata": {
            "method": request.method,
            "path": request.path_qs,
            "timestamp": time_received.isoformat(),
            "delay_seconds": delay,
        },
    }

    return web.json_response(response_data)


async def redirect_handler(_request):
    raise web.HTTPTemporaryRedirect("/redirected")


class SnapshotServer:
    def __init__(self):
        self.size = 2 * 4 * 1024 * 1024 + 17
        self.data = (bytes(range(251)) * ((self.size + 250) // 251))[: self.size]
        self.mode = "inclusive"
        self.requests = []

    async def configure(self, request):
        self.mode = (await request.json())["mode"]
        self.requests.clear()
        return web.Response()

    async def get_requests(self, _request):
        return web.json_response(self.requests)

    async def snapshot(self, request):
        self.requests.append(
            {"path": request.path_qs, "range": request.headers.get("Range")}
        )

        if request.path == "/node/snapshot":
            if self.mode == "not_found" or (
                self.mode == "retry" and len(self.requests) == 1
            ):
                return web.Response(status=404, text="No suitable snapshot")
            if self.mode == "discovery_error":
                return web.Response(status=500, text="Snapshot unavailable")
            if self.mode == "unexpected_status":
                return web.Response(status=200, text="Not a partial response")
            if self.mode == "no_location":
                return web.Response(status=308)
            location = (
                "/node/snapshot"
                if self.mode == "redirect_loop"
                else "/node/snapshot/redirect"
            )
            return web.Response(
                status=308, headers={"Location": location}, body=b"Redirect body"
            )

        if request.match_info["name"] == "redirect":
            return web.Response(
                status=308,
                headers={"Location": "/node/snapshot/snapshot-test.committed"},
                body=b"Another redirect body",
            )

        match = re.fullmatch(r"bytes=(\d+)-(\d+)", request.headers["Range"])
        assert match is not None, request.headers
        start, end = map(int, match.groups())
        end = min(end, self.size - 1)
        if self.mode == "chunk_error" and start != 0:
            return web.Response(status=500, text="Snapshot chunk unavailable")
        if self.mode == "wrong_start":
            start += 1
        if self.mode == "wrong_end":
            end += 1

        # CCF 6.x used exclusive ends; 7.x uses HTTP-style inclusive ends.
        header_end = end + 1 if self.mode == "exclusive" else end
        return web.Response(
            status=206,
            headers={"Content-Range": f"bytes {start}-{header_end}/{self.size}"},
            body=self.data[start : end + 1],
        )

    async def headers(self, request):
        overflow = 2**64
        ranges = {
            "inclusive": "bytes 2-4/10",
            "exclusive": "bytes 2-5/10",
            "missing_range": None,
            "unit": "items 2-4/10",
            "missing_start": "bytes -4/10",
            "missing_end": "bytes 2-/10",
            "missing_total": "bytes 2-4",
            "invalid_start": "bytes x-4/10",
            "invalid_end": "bytes 2-x/10",
            "invalid_total": "bytes 2-4/x",
            "overflow_start": f"bytes {overflow}-4/10",
            "overflow_end": f"bytes 2-{overflow}/10",
            "overflow_total": f"bytes 2-4/{overflow}",
            "length_mismatch": "bytes 2-6/10",
            "missing_length": "bytes 2-4/10",
        }
        case = request.match_info["case"]
        content_range = ranges[case]
        headers = {} if content_range is None else {"Content-Range": content_range}
        if case == "missing_length":
            response = web.StreamResponse(status=206, headers=headers)
            response.enable_chunked_encoding()
            await response.prepare(request)
            await response.write(b"abc")
            await response.write_eof()
            return response
        return web.Response(status=206, headers=headers, body=b"abc")


def make_self_signed_cert(san_dns):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, san_dns)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san_dns)]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    return cert_pem, key_pem


def write_tls_files(cert_path, cert_pem, key_path, key_pem):
    with open(cert_path, "w", encoding="utf-8") as cert_file:
        cert_file.write(cert_pem)
    with open(key_path, "w", encoding="utf-8") as key_file:
        key_file.write(key_pem)


async def main():
    app = web.Application()
    snapshots = SnapshotServer()
    app.router.add_post("/snapshot-test/configure", snapshots.configure)
    app.router.add_get("/snapshot-test/requests", snapshots.get_requests)
    app.router.add_get("/snapshot-test/headers/{case}", snapshots.headers)
    app.router.add_get("/node/snapshot", snapshots.snapshot)
    app.router.add_get("/node/snapshot/{name}", snapshots.snapshot)
    app.router.add_route("*", "/redirect", redirect_handler)
    app.router.add_route("*", "/{path:.*}", echo_handler)

    runner = web.AppRunner(app)
    await runner.setup()

    base_addr = "127.0.0.1"
    site = web.TCPSite(runner, base_addr, 0)
    await site.start()

    sockets = site._server.sockets
    if not sockets:
        raise RuntimeError("Failed to start server")
    port = sockets[0].getsockname()[1]
    addr = f"{base_addr}:{port}"

    print(f"Echo server running on http://{addr}")

    # A second, TLS-enabled endpoint used to exercise curl's certificate
    # hostname verification (CURLOPT_SSL_VERIFYHOST). Its self-signed
    # certificate has a single dNSName SAN that intentionally does not cover
    # the loopback IP it is served on, so a client dialing the IP with
    # VERIFYHOST=2 must reject it, while one dialing the SAN name (resolved to
    # the same address) accepts it.
    tls_san = "ccf-curl-test.invalid"
    tls_cert_pem, tls_key_pem = make_self_signed_cert(tls_san)

    with tempfile.TemporaryDirectory() as tls_dir:
        cert_path = os.path.join(tls_dir, "tls_cert.pem")
        key_path = os.path.join(tls_dir, "tls_key.pem")
        await asyncio.to_thread(
            write_tls_files, cert_path, tls_cert_pem, key_path, tls_key_pem
        )

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert_path, key_path)

        tls_site = web.TCPSite(runner, base_addr, 0, ssl_context=ssl_context)
        await tls_site.start()

        tls_sockets = tls_site._server.sockets
        if not tls_sockets:
            raise RuntimeError("Failed to start TLS server")
        tls_port = tls_sockets[0].getsockname()[1]
        tls_addr = f"{base_addr}:{tls_port}"

        print(f"TLS server running on https://{tls_addr} (cert SAN {tls_san})")

        snapshot_cert_pem, snapshot_key_pem = make_self_signed_cert("localhost")
        snapshot_cert_path = os.path.join(tls_dir, "snapshot_cert.pem")
        snapshot_key_path = os.path.join(tls_dir, "snapshot_key.pem")
        await asyncio.to_thread(
            write_tls_files,
            snapshot_cert_path,
            snapshot_cert_pem,
            snapshot_key_path,
            snapshot_key_pem,
        )
        snapshot_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        snapshot_ssl.load_cert_chain(snapshot_cert_path, snapshot_key_path)
        snapshot_site = web.TCPSite(runner, base_addr, 0, ssl_context=snapshot_ssl)
        await snapshot_site.start()
        snapshot_sockets = snapshot_site._server.sockets
        if not snapshot_sockets:
            raise RuntimeError("Failed to start snapshot TLS server")
        snapshot_port = snapshot_sockets[0].getsockname()[1]

        env = os.environ.copy()
        env["ECHO_SERVER_ADDR"] = str(addr)
        env["TLS_SERVER_ADDR"] = str(tls_addr)
        env["TLS_SERVER_SAN"] = tls_san
        env["TLS_SERVER_CA"] = cert_path
        env["SNAPSHOT_SERVER_ADDR"] = f"localhost:{snapshot_port}"
        env["SNAPSHOT_SERVER_CA"] = snapshot_cert_path

        cmd = "./curl_test"
        process = await asyncio.create_subprocess_shell(cmd, env=env)
        await process.wait()
        sys.exit(process.returncode)


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
