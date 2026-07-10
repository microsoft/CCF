# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, UTC
import asyncio
import os
import random
import ssl
import tempfile


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


async def main():
    app = web.Application()
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
        with open(cert_path, "w", encoding="utf-8") as cert_file:
            cert_file.write(tls_cert_pem)
        with open(key_path, "w", encoding="utf-8") as key_file:
            key_file.write(tls_key_pem)

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

        env = os.environ.copy()
        env["ECHO_SERVER_ADDR"] = str(addr)
        env["TLS_SERVER_ADDR"] = str(tls_addr)
        env["TLS_SERVER_SAN"] = tls_san
        env["TLS_SERVER_CA"] = cert_path

        cmd = "./curl_test"
        process = await asyncio.create_subprocess_shell(cmd, env=env)
        await process.wait()
        exit(process.returncode)


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
