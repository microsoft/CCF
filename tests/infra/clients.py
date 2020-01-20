# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import socket
import ssl
import msgpack
import struct
import select
import contextlib
import json
import time
import os
import subprocess
import tempfile
import base64
import requests
from requests_http_signature import HTTPSignatureAuth
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import asymmetric
from websocket import create_connection

from loguru import logger as LOG


def truncate(string, max_len=256):
    if len(string) > max_len:
        return string[: max_len - 3] + "..."
    else:
        return string


class Request:
    def __init__(self, id, method, params, readonly_hint=None, jsonrpc="2.0"):
        self.id = id
        self.method = method
        self.params = params
        self.jsonrpc = jsonrpc
        self.readonly_hint = readonly_hint

    def to_dict(self):
        rpc = {
            "id": self.id,
            "method": self.method,
            "jsonrpc": self.jsonrpc,
            "params": self.params,
        }
        if self.readonly_hint is not None:
            rpc["readonly"] = self.readonly_hint
        return rpc

    def to_msgpack(self):
        return msgpack.packb(self.to_dict(), use_bin_type=True)

    def to_json(self):
        return json.dumps(self.to_dict()).encode()


class Response:
    def __init__(
        self,
        id,
        result=None,
        error=None,
        commit=None,
        term=None,
        global_commit=None,
        jsonrpc="2.0",
    ):
        self.id = id
        self.result = result
        self.error = error
        self.jsonrpc = jsonrpc
        self.commit = commit
        self.term = term
        self.global_commit = global_commit
        self._attrs = set(locals()) - {"self"}

    def to_dict(self):
        d = {
            "id": self.id,
            "jsonrpc": self.jsonrpc,
            "commit": self.commit,
            "global_commit": self.global_commit,
            "term": self.term,
        }
        if self.result is not None:
            d["result"] = self.result
        else:
            d["error"] = self.error
        return d

    def _from_parsed(self, parsed):
        unexpected = parsed.keys() - self._attrs
        if unexpected:
            raise ValueError(f"Unexpected keys in response: {unexpected}")
        for attr, value in parsed.items():
            setattr(self, attr, value)

    def from_msgpack(self, data):
        parsed = msgpack.unpackb(data, raw=False)
        self._from_parsed(parsed)

    def from_json(self, data):
        parsed = json.loads(data.decode())
        self._from_parsed(parsed)


def human_readable_size(n):
    suffixes = ("B", "KB", "MB", "GB")
    i = 0
    while n >= 1024 and i < len(suffixes) - 1:
        n /= 1024.0
        i += 1
    return f"{n:,.2f} {suffixes[i]}"


class FramedTLSClient:
    def __init__(self, host, port, cert=None, key=None, ca=None):
        self.host = host
        self.port = port
        self.cert = cert
        self.key = key
        self.ca = ca
        self.context = None
        self.sock = None
        self.conn = None

    def connect(self):
        if self.ca:
            self.context = ssl.create_default_context(cafile=self.ca)

            # Auto detect EC curve to use based on server CA
            ca_bytes = open(self.ca, "rb").read()
            ca_curve = (
                x509.load_pem_x509_certificate(ca_bytes, default_backend())
                .public_key()
                .curve
            )
            if isinstance(ca_curve, asymmetric.ec.SECP256K1):
                self.context.set_ecdh_curve("secp256k1")
        else:
            self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        if self.cert and self.key:
            self.context.load_cert_chain(certfile=self.cert, keyfile=self.key)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn = self.context.wrap_socket(
            self.sock, server_side=False, server_hostname=self.host
        )
        self.conn.connect((self.host, self.port))

    def send(self, msg):
        LOG.trace(f"Sending {human_readable_size(len(msg))} message")
        frame = struct.pack("<I", len(msg)) + msg
        self.conn.sendall(frame)

    def _read(self):
        (size,) = struct.unpack("<I", self.conn.recv(4))
        LOG.trace(f"Reading {human_readable_size(size)} response")
        data = self.conn.recv(size)
        while len(data) < size:
            data += self.conn.recv(size - len(data))
        return data

    def read(self):
        for _ in range(5000):
            r, _, _ = select.select([self.conn], [], [], 0)
            if r:
                return self._read()
            else:
                time.sleep(0.01)

    def disconnect(self):
        self.conn.close()


class Stream:
    def __init__(self, jsonrpc="2.0", format="msgpack"):
        self.jsonrpc = jsonrpc
        self.seqno = 0
        self.pending = {}
        self.format = format

    def request(self, method, params, readonly_hint=None):
        r = Request(self.seqno, method, params, readonly_hint, self.jsonrpc)
        self.seqno += 1
        return r

    def response(self, id):
        return self.pending.pop(id, None)

    def update(self, msg):
        r = Response(0)
        getattr(r, f"from_{self.format}")(msg)
        self.pending[r.id] = r


class RPCLogger:
    def log_request(self, request, name, description):
        LOG.info(
            truncate(
                f"{name} #{request.id} {request.method} {request.params}"
                + (
                    f" (RO hint: {request.readonly_hint})"
                    if request.readonly_hint is not None
                    else ""
                )
                + f"{description}"
            )
        )

    def log_response(self, id, response):
        LOG.debug(
            truncate(
                "#{} {}".format(
                    id,
                    {
                        k: v
                        for k, v in (response.__dict__ or {}).items()
                        if not k.startswith("_")
                    }
                    if response
                    else None,
                )
            )
        )


class RPCFileLogger(RPCLogger):
    def __init__(self, path):
        self.path = path

    def log_request(self, request, name, description):
        with open(self.path, "a") as f:
            f.write(">> Request:" + os.linesep)
            json.dump(request.to_dict(), f, indent=2)
            f.write(os.linesep)

    def log_response(self, id, response):
        with open(self.path, "a") as f:
            f.write(f"<< Response {id} :" + os.linesep)
            json.dump(response.to_dict() if response else "None", f, indent=2)
            f.write(os.linesep)


class CCFConnectionException(Exception):
    pass


class FramedTLSJSONRPCClient:
    def __init__(
        self,
        host,
        port,
        cert=None,
        key=None,
        ca=None,
        version="2.0",
        format="msgpack",
        connection_timeout=3,
        *args,
        **kwargs,
    ):
        self.client = FramedTLSClient(host, int(port), cert, key, ca)
        self.stream = Stream(version, format=format)
        self.format = format

        while connection_timeout >= 0:
            connection_timeout -= 0.1
            try:
                self.connect()
                break
            except (ssl.SSLError, ssl.SSLCertVerificationError):
                if connection_timeout < 0:
                    raise CCFConnectionException
            time.sleep(0.1)

    def connect(self):
        return self.client.connect()

    def disconnect(self):
        return self.client.disconnect()

    def request(self, request):
        self.client.send(getattr(request, f"to_{self.format}")())
        return request.id

    def tick(self):
        msg = self.client.read()
        self.stream.update(msg)

    def response(self, id):
        self.tick()
        return self.stream.response(id)


# We keep this around in a limited fashion still, because
# the resulting logs nicely illustrate manual usage in a way using requests doesn't


class CurlClient:
    def __init__(
        self,
        host,
        port,
        cert,
        key,
        ca,
        version,
        format,
        connection_timeout,
        *args,
        **kwargs,
    ):
        self.host = host
        self.port = port
        self.cert = cert
        self.key = key
        self.ca = ca
        self.format = "json"
        self.connection_timeout = connection_timeout
        self.stream = Stream(version, "json")

    def _just_request(self, request, is_signed=False):
        with tempfile.NamedTemporaryFile() as nf:
            msg = getattr(request, f"to_{self.format}")()
            LOG.debug(f"Going to send {msg}")
            nf.write(msg)
            nf.flush()
            if is_signed:
                cmd = ["./scurl.sh"]
            else:
                cmd = ["curl"]

            cmd += [
                f"https://{self.host}:{self.port}/{request.method}",
                "-H",
                "Content-Type: application/json",
                "--data-binary",
                f"@{nf.name}",
                "-w \\n%{http_code}",
            ]

            if self.ca:
                cmd.extend(["--cacert", self.ca])
            if self.key:
                cmd.extend(["--key", self.key])
            if self.cert:
                cmd.extend(["--cert", self.cert])
            LOG.debug(f"Running: {' '.join(cmd)}")
            rc = subprocess.run(cmd, capture_output=True)

            if rc.returncode != 0:
                if rc.returncode == 60:
                    raise CCFConnectionException
                LOG.error(rc.stderr)
                raise RuntimeError(f"Curl failed with return code {rc.returncode}")

            # The response status code is displayed on the last line of
            # the output (via -w option)
            rep, status_code = rc.stdout.decode().rsplit("\n", 1)
            if int(status_code) != 200:
                LOG.error(rep)
                raise RuntimeError(f"Curl failed with status code {status_code}")

            self.stream.update(rep.encode())
        return request.id

    def _request(self, request, is_signed=False):
        while self.connection_timeout >= 0:
            self.connection_timeout -= 0.1
            try:
                rid = self._just_request(request, is_signed)
                self._request = self._just_request
                return rid
            except CCFConnectionException:
                if self.connection_timeout < 0:
                    raise
            time.sleep(0.1)

    def request(self, request):
        return self._request(request, is_signed=False)

    def signed_request(self, request):
        return self._request(request, is_signed=True)

    def response(self, id):
        return self.stream.response(id)

    def disconnect(self):
        pass


class RequestClient:
    def __init__(
        self,
        host,
        port,
        cert,
        key,
        ca,
        version,
        format,
        connection_timeout,
        request_timeout,
    ):
        self.host = host
        self.port = port
        self.cert = cert
        self.key = key
        self.ca = ca
        self.format = "json"
        self.stream = Stream(version, "json")
        self.request_timeout = request_timeout
        self.connection_timeout = connection_timeout

    def _just_request(self, request):
        rep = requests.post(
            f"https://{self.host}:{self.port}/{request.method}",
            json=request.to_dict(),
            cert=(self.cert, self.key),
            verify=self.ca,
            timeout=self.request_timeout,
        )
        self.stream.update(rep.content)
        return request.id

    def request(self, request):
        while self.connection_timeout >= 0:
            self.connection_timeout -= 0.1
            try:
                rid = self._just_request(request)
                self.request = self._just_request
                return rid
            except (requests.exceptions.ReadTimeout, requests.exceptions.SSLError) as e:
                if self.connection_timeout < 0:
                    raise CCFConnectionException
            time.sleep(0.1)

    def signed_request(self, request):
        with open(self.key, "rb") as k:
            rep = requests.post(
                f"https://{self.host}:{self.port}/{request.method}",
                json=request.to_dict(),
                cert=(self.cert, self.key),
                verify=self.ca,
                timeout=self.request_timeout,
                # key_id needs to be specified but is unused
                auth=HTTPSignatureAuth(
                    algorithm="ecdsa-sha256",
                    key=k.read(),
                    key_id="tls",
                    headers=["(request-target)", "Date"],
                ),
            )
            self.stream.update(rep.content)
        return request.id

    def response(self, id):
        return self.stream.response(id)

    def disconnect(self):
        pass


class WSClient:
    def __init__(
        self,
        host,
        port,
        cert,
        key,
        ca,
        version,
        format,
        connection_timeout,
        request_timeout,
    ):
        self.host = host
        self.port = port
        self.cert = cert
        self.key = key
        self.ca = ca
        self.format = "json"
        self.stream = Stream(version, "json")
        self.request_timeout = request_timeout

    def request(self, request):
        ws = create_connection(
            f"wss://{self.host}:{self.port}",
            sslopt={"certfile": self.cert, "keyfile": self.key, "ca_certs": self.ca},
        )
        # TODO: Support sending data over websocket
        # ws.send(request.to_json())
        # res = ws.recv()
        # ws.close()
        # self.stream.update(rep.content)
        return request.id

    def signed_request(self, request):
        raise NotImplementedError("Signed requests not yet implemented over WebSockets")

    def response(self, id):
        return self.stream.response(id)

    def disconnect(self):
        pass


class CCFClient:
    def __init__(self, *args, **kwargs):
        self.prefix = kwargs.pop("prefix")
        self.description = kwargs.pop("description")
        self.rpc_loggers = (RPCLogger(),)
        self.name = "[{}:{}]".format(kwargs.get("host"), kwargs.get("port"))

        if os.getenv("HTTP"):
            if os.getenv("CURL_CLIENT"):
                self.client_impl = CurlClient(*args, **kwargs)
            elif os.getenv("WEBSOCKETS_CLIENT"):
                self.client_impl = WSClient(*args, **kwargs)
            else:
                self.client_impl = RequestClient(*args, **kwargs)
        else:
            self.client_impl = FramedTLSJSONRPCClient(*args, **kwargs)

    def disconnect(self):
        self.client_impl.disconnect()

    def request(self, method, params, *args, **kwargs):
        r = self.client_impl.stream.request(
            f"{self.prefix}/{method}", params, *args, **kwargs
        )
        if self.description:
            description = f" ({self.description})"
        for logger in self.rpc_loggers:
            logger.log_request(r, self.name, description)

        self.client_impl.request(r)
        return r.id

    def signed_request(self, method, params, *args, **kwargs):
        r = self.client_impl.stream.request(
            f"{self.prefix}/{method}", params, *args, **kwargs
        )
        if self.description:
            description = f" ({self.description}) [signed]"
        for logger in self.rpc_loggers:
            logger.log_request(r, self.name, description)

        return self.client_impl.signed_request(r)

    def response(self, id):
        r = self.client_impl.response(id)
        for logger in self.rpc_loggers:
            logger.log_response(id, r)
        return r

    def do(self, *args, **kwargs):
        expected_result = None
        expected_error_code = None
        if "expected_result" in kwargs:
            expected_result = kwargs.pop("expected_result")
        if "expected_error_code" in kwargs:
            expected_error_code = kwargs.pop("expected_error_code")

        id = self.request(*args, **kwargs)
        r = self.response(id)

        if expected_result is not None:
            assert expected_result == r.result

        if expected_error_code is not None:
            assert expected_error_code == r.error["code"]
        return r

    def rpc(self, *args, **kwargs):
        if "signed" in kwargs and kwargs.pop("signed"):
            id = self.signed_request(*args, **kwargs)
        else:
            id = self.request(*args, **kwargs)
        return self.response(id)


@contextlib.contextmanager
def client(
    host,
    port,
    cert=None,
    key=None,
    ca=None,
    version="2.0",
    format="json" if os.getenv("HTTP") else "msgpack",
    description=None,
    log_file=None,
    prefix="users",
    connection_timeout=3,
    request_timeout=3,
):
    c = CCFClient(
        host=host,
        port=port,
        cert=cert,
        key=key,
        ca=ca,
        version=version,
        format=format,
        description=description,
        prefix=prefix,
        connection_timeout=connection_timeout,
        request_timeout=request_timeout,
    )

    if log_file is not None:
        c.rpc_loggers += (RPCFileLogger(log_file),)

    try:
        yield c
    finally:
        c.disconnect()
