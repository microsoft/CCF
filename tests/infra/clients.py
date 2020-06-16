# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import contextlib
import json
import time
import os
import subprocess
import tempfile
import urllib.parse
from http.client import HTTPResponse
from io import BytesIO
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import struct

import requests
from loguru import logger as LOG
from requests_http_signature import HTTPSignatureAuth
import websocket


def truncate(string, max_len=256):
    if len(string) > max_len:
        return string[: max_len - 3] + "..."
    else:
        return string


CCF_TX_SEQNO_HEADER = "x-ccf-tx-seqno"
CCF_TX_VIEW_HEADER = "x-ccf-tx-view"
# Deprecated, will be removed
CCF_GLOBAL_COMMIT_HEADER = "x-ccf-global-commit"


class Request:
    def __init__(
        self, method, params=None, http_verb="POST", headers=None
    ):
        if headers is None:
            headers = {}

        self.method = method
        self.params = params
        self.http_verb = http_verb
        self.headers = headers


def int_or_none(v):
    return int(v) if v is not None else None


class FakeSocket:
    def __init__(self, bs):
        self.file = BytesIO(bs)

    def makefile(self, *args, **kwargs):
        return self.file


class Response:
    def __init__(self, status, result, error, seqno, view, global_commit, headers):
        self.status = status
        self.result = result
        self.error = error
        self.seqno = seqno
        self.view = view
        self.global_commit = global_commit
        self.headers = headers

    def to_dict(self):
        d = {
            "seqno": self.seqno,
            "global_commit": self.global_commit,
            "view": self.view,
        }
        if self.result is not None:
            d["result"] = self.result
        else:
            d["error"] = self.error
        return d

    def __str__(self):
        versioned = (self.view, self.seqno) != (None, None)
        body = self.result if f"{self.status}"[0] == "2" else self.error
        return (
            f"{self.status} "
            + (f"@{self.view}.{self.seqno} " if versioned else "")
            + truncate(f"{body}")
        )

    @staticmethod
    def from_requests_response(rr):
        content_type = rr.headers.get("content-type")
        if content_type == "application/json":
            parsed_body = rr.json()
        elif content_type == "text/plain":
            parsed_body = rr.text
        elif content_type is None:
            parsed_body = None
        else:
            raise ValueError(f"Unhandled content type: {content_type}")

        return Response(
            status=rr.status_code,
            result=parsed_body if rr.ok else None,
            error=None if rr.ok else parsed_body,
            seqno=int_or_none(rr.headers.get(CCF_TX_SEQNO_HEADER)),
            view=int_or_none(rr.headers.get(CCF_TX_VIEW_HEADER)),
            global_commit=int_or_none(rr.headers.get(CCF_GLOBAL_COMMIT_HEADER)),
            headers=rr.headers,
        )

    @staticmethod
    def from_raw(raw):
        sock = FakeSocket(raw)
        response = HTTPResponse(sock)
        response.begin()
        raw_body = response.read(raw)
        ok = response.status == 200

        content_type = response.headers.get("content-type")
        if content_type == "application/json":
            parsed_body = json.loads(raw_body)
        elif content_type == "text/plain":
            parsed_body = raw_body.decode()
        elif content_type is None:
            parsed_body = None
        else:
            raise ValueError(f"Unhandled content type: {content_type}")

        return Response(
            status=response.status,
            result=parsed_body if ok else None,
            error=None if ok else parsed_body,
            seqno=int_or_none(response.getheader(CCF_TX_SEQNO_HEADER)),
            view=int_or_none(response.getheader(CCF_TX_VIEW_HEADER)),
            global_commit=int_or_none(response.getheader(CCF_GLOBAL_COMMIT_HEADER)),
            headers=response.headers,
        )


def human_readable_size(n):
    suffixes = ("B", "KB", "MB", "GB")
    i = 0
    while n >= 1024 and i < len(suffixes) - 1:
        n /= 1024.0
        i += 1
    return f"{n:,.2f} {suffixes[i]}"


class RPCLogger:
    def log_request(self, request, name, description):
        LOG.info(
            f"{name} {request.http_verb} /{request.method}"
            + (truncate(f" {request.params}") if request.params is not None else "")
            + f"{description}"
        )

    def log_response(self, response):
        LOG.debug(response)


class RPCFileLogger(RPCLogger):
    def __init__(self, path):
        self.path = path

    def log_request(self, request, name, description):
        with open(self.path, "a") as f:
            f.write(f">> Request: {request.http_verb} /{request.method}" + os.linesep)
            json.dump(request.params, f, indent=2)
            f.write(os.linesep)

    def log_response(self, response):
        with open(self.path, "a") as f:
            f.write("<< Response:" + os.linesep)
            json.dump(response.to_dict() if response else "None", f, indent=2)
            f.write(os.linesep)


class CCFConnectionException(Exception):
    pass


def build_query_string(params):
    return "&".join(
        f"{urllib.parse.quote_plus(k)}={urllib.parse.quote_plus(json.dumps(v))}"
        for k, v in params.items()
    )


def get_curve(ca_file):
    # Auto detect EC curve to use based on server CA
    ca_bytes = open(ca_file, "rb").read()
    return (
        x509.load_pem_x509_certificate(ca_bytes, default_backend()).public_key().curve
    )


class CurlClient:
    """
    We keep this around in a limited fashion still, because
    the resulting logs nicely illustrate manual usage in a way using the requests API doesn't
    """

    def __init__(
        self, host, port, cert, key, ca, binary_dir, request_timeout, *args, **kwargs,
    ):
        self.host = host
        self.port = port
        self.cert = cert
        self.key = key
        self.ca = ca
        self.binary_dir = binary_dir
        self.request_timeout = request_timeout

        ca_curve = get_curve(self.ca)
        if ca_curve.name == "secp256k1":
            raise RuntimeError(
                f"CurlClient cannot perform TLS handshake with {ca_curve.name} ECDH curve. "
                "Use RequestClient class instead."
            )

    def request(self, request, is_signed=False):
        with tempfile.NamedTemporaryFile() as nf:
            if is_signed:
                cmd = [os.path.join(self.binary_dir, "scurl.sh")]
            else:
                cmd = ["curl"]

            url = f"https://{self.host}:{self.port}/{request.method}"

            is_get = request.http_verb == "GET"
            if is_get:
                if request.params is not None:
                    url += f"?{build_query_string(request.params)}"

            cmd += [
                url,
                "-X",
                request.http_verb,
                "-i",
                f"-m {self.request_timeout}",
            ]

            if not is_get:
                if request.params is None:
                    msg_bytes = bytes()
                elif isinstance(request.params, bytes):
                    msg_bytes = request.params
                else:
                    msg_bytes = json.dumps(request.params).encode()
                LOG.debug(f"Writing request body: {msg_bytes}")
                nf.write(msg_bytes)
                nf.flush()
                cmd.extend(["--data-binary", f"@{nf.name}"])

            # Set requested headers first - so they take precedence over defaults
            for k, v in request.headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

            cmd.extend(["-H", "Content-Type: application/json"])

            if self.ca:
                cmd.extend(["--cacert", self.ca])
            if self.key:
                cmd.extend(["--key", self.key])
            if self.cert:
                cmd.extend(["--cert", self.cert])

            LOG.debug(f"Running: {' '.join(cmd)}")
            rc = subprocess.run(cmd, capture_output=True, check=False)

            if rc.returncode != 0:
                if rc.returncode == 60:  # PEER_FAILED_VERIFICATION
                    raise CCFConnectionException
                if rc.returncode == 28:  # OPERATION_TIMEDOUT
                    raise TimeoutError
                LOG.error(rc.stderr)
                raise RuntimeError(f"Curl failed with return code {rc.returncode}")

            return Response.from_raw(rc.stdout)


class TlsAdapter(HTTPAdapter):
    def __init__(self, ca_file):
        self.ca_curve = get_curve(ca_file)
        super().__init__()

    # pylint: disable=signature-differs
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context()
        context.set_ecdh_curve(self.ca_curve.name)
        kwargs["ssl_context"] = context
        return super(TlsAdapter, self).init_poolmanager(*args, **kwargs)


class RequestClient:
    def __init__(
        self, host, port, cert, key, ca, request_timeout, *args, **kwargs,
    ):
        self.host = host
        self.port = port
        self.cert = cert
        self.key = key
        self.ca = ca
        self.request_timeout = request_timeout
        self.session = requests.Session()
        self.session.verify = self.ca
        self.session.cert = (self.cert, self.key)
        self.session.mount("https://", TlsAdapter(self.ca))

    def request(self, request, is_signed=False):
        auth_value = None
        if is_signed:
            auth_value = HTTPSignatureAuth(
                algorithm="ecdsa-sha256",
                key=open(self.key, "rb").read(),
                # key_id needs to be specified but is unused
                key_id="tls",
                headers=["(request-target)", "Date", "Content-Length", "Content-Type",],
            )

        extra_headers = {}
        extra_headers.update(request.headers)

        request_args = {
            "method": request.http_verb,
            "url": f"https://{self.host}:{self.port}/{request.method}",
            "auth": auth_value,
            "headers": extra_headers,
        }

        is_get = request.http_verb == "GET"
        if request.params is not None:
            if is_get:
                request_args["params"] = build_query_string(request.params)
            else:
                request_args["json"] = request.params

        try:
            response = self.session.request(
                timeout=self.request_timeout, **request_args
            )
        except requests.exceptions.ReadTimeout as exc:
            raise TimeoutError from exc
        except requests.exceptions.SSLError as exc:
            raise CCFConnectionException from exc
        except Exception as exc:
            raise RuntimeError("Request client failed with unexpected error") from exc

        return Response.from_requests_response(response)


class WSClient:
    def __init__(
        self, host, port, cert, key, ca, request_timeout, *args, **kwargs,
    ):
        self.host = host
        self.port = port
        self.cert = cert
        self.key = key
        self.ca = ca
        self.request_timeout = request_timeout
        self.ws = None

    def request(self, request, is_signed=False):
        assert not is_signed

        if not self.ws:
            LOG.info("Creating WSS connection")
            try:
                self.ws = websocket.create_connection(
                    f"wss://{self.host}:{self.port}",
                    sslopt={
                        "certfile": self.cert,
                        "keyfile": self.key,
                        "ca_certs": self.ca,
                    },
                    timeout=self.request_timeout,
                )
            except Exception as exc:
                raise CCFConnectionException from exc
        payload = json.dumps(request.params).encode()
        path = ("/" + request.method).encode()
        header = struct.pack("<h", len(path)) + path
        # FIN, no RSV, BIN, UNMASKED every time, because it's all we support right now
        frame = websocket.ABNF(
            1, 0, 0, 0, websocket.ABNF.OPCODE_BINARY, 0, header + payload
        )
        self.ws.send_frame(frame)
        out = self.ws.recv_frame().data
        (status,) = struct.unpack("<h", out[:2])
        (seqno,) = struct.unpack("<Q", out[2:10])
        (view,) = struct.unpack("<Q", out[10:18])
        (global_commit,) = struct.unpack("<Q", out[18:26])
        payload = out[26:]
        if status == 200:
            result = json.loads(payload) if payload else None
            error = None
        else:
            result = None
            error = payload.decode()
        return Response(status, result, error, seqno, view, global_commit, headers={})


class CCFClient:
    def __init__(self, *args, **kwargs):
        self.prefix = kwargs.pop("prefix")
        self.description = kwargs.pop("description")
        self.connection_timeout = kwargs.pop("connection_timeout")
        self.rpc_loggers = (RPCLogger(),)
        self.name = "[{}:{}]".format(kwargs.get("host"), kwargs.get("port"))

        if os.getenv("CURL_CLIENT"):
            self.client_impl = CurlClient(*args, **kwargs)
        elif os.getenv("WEBSOCKETS_CLIENT") or kwargs.get("ws"):
            self.client_impl = WSClient(*args, **kwargs)
        else:
            self.client_impl = RequestClient(*args, **kwargs)

    def _response(self, response):
        for logger in self.rpc_loggers:
            logger.log_response(response)
        return response

    # pylint: disable=method-hidden
    def _just_rpc(self, method, *args, **kwargs):
        is_signed = "signed" in kwargs and kwargs.pop("signed")
        r = Request(f"{self.prefix}/{method}", *args, **kwargs)

        description = ""
        if self.description:
            description = f" ({self.description})" + (" [signed]" if is_signed else "")
        for logger in self.rpc_loggers:
            logger.log_request(r, self.name, description)

        return self._response(self.client_impl.request(r, is_signed))

    def rpc(self, *args, **kwargs):
        end_time = time.time() + self.connection_timeout
        while True:
            try:
                response = self._just_rpc(*args, **kwargs)
                # Only the first request gets this timeout logic - future calls
                # call _just_rpc directly
                self.rpc = self._just_rpc
                return response
            except (CCFConnectionException, TimeoutError) as e:
                # If the initial connection fails (e.g. due to node certificate
                # not yet being endorsed by the network) sleep briefly and try again
                if time.time() > end_time:
                    raise CCFConnectionException(
                        f"Connection still failing after {self.connection_timeout}s"
                    ) from e
                LOG.debug(f"Got exception: {e}")
                time.sleep(0.1)

    def get(self, *args, **kwargs):
        return self.rpc(*args, http_verb="GET", **kwargs)


@contextlib.contextmanager
def client(
    host,
    port,
    cert=None,
    key=None,
    ca=None,
    description=None,
    log_file=None,
    prefix="users",
    binary_dir=".",
    connection_timeout=3,
    request_timeout=3,
    ws=False,
):
    c = CCFClient(
        host=host,
        port=port,
        cert=cert,
        key=key,
        ca=ca,
        description=description,
        prefix=prefix,
        binary_dir=binary_dir,
        connection_timeout=connection_timeout,
        request_timeout=request_timeout,
        ws=ws,
    )

    if log_file is not None:
        c.rpc_loggers += (RPCFileLogger(log_file),)

    yield c
