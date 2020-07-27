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
import base64

import requests
from loguru import logger as LOG
from requests_http_signature import HTTPSignatureAuth
import websocket


def truncate(string, max_len=256):
    if len(string) > max_len:
        return f"{string[: max_len]} + {len(string) - max_len} chars"
    else:
        return string


CCF_TX_SEQNO_HEADER = "x-ccf-tx-seqno"
CCF_TX_VIEW_HEADER = "x-ccf-tx-view"
# Deprecated, will be removed
CCF_GLOBAL_COMMIT_HEADER = "x-ccf-global-commit"

DEFAULT_CONNECTION_TIMEOUT_SEC = 3
DEFAULT_REQUEST_TIMEOUT_SEC = 3


class Request:
    def __init__(
        self, path, params=None, http_verb="POST", headers=None, params_in_query=None
    ):
        if headers is None:
            headers = {}

        # TODO: remove
        if params_in_query is None:
            params_in_query = http_verb == "GET"

        self.path = path
        self.params = params
        self.http_verb = http_verb
        self.headers = headers
        self.params_in_query = params_in_query

    def __str__(self):
        return f"{self.http_verb} {self.path} {self.headers}" + (
            truncate(f" {self.params}") if self.params is not None else ""
        )


def int_or_none(v):
    return int(v) if v is not None else None


class FakeSocket:
    def __init__(self, bs):
        self.file = BytesIO(bs)

    def makefile(self, *args, **kwargs):
        return self.file


class Response:
    def __init__(self, status, body, seqno, view, global_commit, headers):
        self.status = status
        self.body = body
        self.seqno = seqno
        self.view = view
        self.global_commit = global_commit
        self.headers = headers

    # TODO: what's this for?
    def to_dict(self):
        return {
            "seqno": self.seqno,
            "global_commit": self.global_commit,
            "view": self.view,
            "body": self.body,
        }

    def __str__(self):
        versioned = (self.view, self.seqno) != (None, None)
        return (
            f"{self.status} "
            + (f"@{self.view}.{self.seqno} " if versioned else "")
            + truncate(f"{self.body}")
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
            body=parsed_body,
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
            body=parsed_body,
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
        self,
        host,
        port,
        cert=None,
        key=None,
        ca=None,
        binary_dir=".",
        request_timeout=DEFAULT_REQUEST_TIMEOUT_SEC,
        **kwargs,
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

            url = f"https://{self.host}:{self.port}{request.path}"

            if request.params_in_query:
                if request.params is not None:
                    url += f"?{build_query_string(request.params)}"

            cmd += [
                url,
                "-X",
                request.http_verb,
                "-i",
                f"-m {self.request_timeout}",
            ]

            if not request.params_in_query and request.params is not None:
                if isinstance(request.params, str) and request.params.startswith("@"):
                    # Request is already a file path - pass it directly
                    cmd.extend(["--data-binary", request.params])
                else:
                    # Write request to temp file
                    if isinstance(request.params, bytes):
                        msg_bytes = request.params
                    else:
                        msg_bytes = json.dumps(request.params).encode()
                    LOG.debug(f"Writing request body: {truncate(msg_bytes)}")
                    nf.write(msg_bytes)
                    nf.flush()
                    cmd.extend(["--data-binary", f"@{nf.name}"])
                if not "content-type" in request.headers:
                    request.headers["content-type"] = "application/json"

            # Set requested headers first - so they take precedence over defaults
            for k, v in request.headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

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
        self.ca_curve = None
        if ca_file is not None:
            self.ca_curve = get_curve(ca_file)
        super().__init__()

    # pylint: disable=signature-differs
    def init_poolmanager(self, *args, **kwargs):
        if self.ca_curve is not None:
            context = create_urllib3_context()
            context.set_ecdh_curve(self.ca_curve.name)
            kwargs["ssl_context"] = context
        return super(TlsAdapter, self).init_poolmanager(*args, **kwargs)


class HTTPSignatureAuth_AlwaysDigest(HTTPSignatureAuth):
    def add_digest(self, request):
        # Add digest of empty body, never leave it blank
        if request.body is None:
            if "digest" not in self.headers:
                self.headers.append("digest")
            digest = self.hasher_constructor(b"").digest()
            request.headers["Digest"] = "SHA-256=" + base64.b64encode(digest).decode()
        else:
            super(HTTPSignatureAuth_AlwaysDigest, self).add_digest(request)


class RequestClient:
    def __init__(
        self,
        host,
        port,
        cert=None,
        key=None,
        ca=None,
        request_timeout=DEFAULT_REQUEST_TIMEOUT_SEC,
        **kwargs,
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
        extra_headers = {}
        extra_headers.update(request.headers)

        auth_value = None
        if is_signed:
            auth_value = HTTPSignatureAuth_AlwaysDigest(
                algorithm="ecdsa-sha256",
                key=open(self.key, "rb").read(),
                # key_id needs to be specified but is unused
                key_id="tls",
                headers=["(request-target)", "Digest", "Content-Length"],
            )

        request_args = {
            "method": request.http_verb,
            "url": f"https://{self.host}:{self.port}{request.path}",
            "auth": auth_value,
            "headers": extra_headers,
            "allow_redirects": False,
        }

        if request.params is not None:
            request_params = request.params
            if isinstance(request.params, str) and request.params.startswith("@"):
                # Request is a file path - read contents, assume json
                request_params = json.load(open(request.params[1:]))

            if request.params_in_query:
                request_args["params"] = build_query_string(request_params)
            else:
                request_args["json"] = request_params

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
        self,
        host,
        port,
        cert=None,
        key=None,
        ca=None,
        request_timeout=DEFAULT_REQUEST_TIMEOUT_SEC,
        **kwargs,
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
        path = (request.path).encode()
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
        # TODO: move out the decoding!
        if status == 200:
            body = json.loads(payload) if payload else None
        else:
            body = payload.decode()
        return Response(status, body, seqno, view, global_commit, headers={})


class CCFClient:
    def __init__(self, host, port, *args, **kwargs):
        self.description = (
            kwargs.pop("description") if "description" in kwargs else None
        )
        self.connection_timeout = (
            kwargs.pop("connection_timeout")
            if "connection_timeout" in kwargs
            else DEFAULT_CONNECTION_TIMEOUT_SEC
        )
        self.name = f"[{host}:{port}]"

        if os.getenv("CURL_CLIENT"):
            self.client_impl = CurlClient(host, port, *args, **kwargs)
        elif os.getenv("WEBSOCKETS_CLIENT") or kwargs.get("ws"):
            self.client_impl = WSClient(host, port, *args, **kwargs)
        else:
            self.client_impl = RequestClient(host, port, *args, **kwargs)

    def _response(self, response):
        LOG.info(response)
        return response

    # pylint: disable=method-hidden
    def _direct_call(self, method, *args, **kwargs):
        is_signed = "signed" in kwargs and kwargs.pop("signed")
        r = Request(method, *args, **kwargs)

        description = ""
        if self.description:
            description = f"({self.description})" + (" [signed]" if is_signed else "")
        LOG.info(f"{self.name} {r} ({description})")
        return self._response(self.client_impl.request(r, is_signed))

    def call(self, *args, **kwargs):
        end_time = time.time() + self.connection_timeout
        while True:
            try:
                response = self._direct_call(*args, **kwargs)
                # Only the first request gets this timeout logic - future calls
                # call _direct_call directly
                self.call = self._direct_call
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
        return self.call(*args, http_verb="GET", **kwargs)

    def post(self, *args, **kwargs):
        return self.call(*args, http_verb="POST", **kwargs)

    def put(self, *args, **kwargs):
        return self.call(*args, http_verb="PUT", **kwargs)

    def delete(self, *args, **kwargs):
        return self.call(*args, http_verb="DELETE", **kwargs)

    def head(self, *args, **kwargs):
        return self.call(*args, http_verb="HEAD", **kwargs)


@contextlib.contextmanager
def client(
    host,
    port,
    cert=None,
    key=None,
    ca=None,
    description=None,
    binary_dir=".",
    connection_timeout=DEFAULT_CONNECTION_TIMEOUT_SEC,
    request_timeout=DEFAULT_REQUEST_TIMEOUT_SEC,
    ws=False,
):
    c = CCFClient(
        host=host,
        port=port,
        cert=cert,
        key=key,
        ca=ca,
        description=description,
        binary_dir=binary_dir,
        connection_timeout=connection_timeout,
        request_timeout=request_timeout,
        ws=ws,
    )

    yield c
