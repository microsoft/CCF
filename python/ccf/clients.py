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

import ccf.commit


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
DEFAULT_COMMIT_TIMEOUT_SEC = 3


def build_query_string(params):
    return "&".join(
        f"{urllib.parse.quote_plus(k)}={urllib.parse.quote_plus(json.dumps(v))}"
        for k, v in params.items()
    )


class Request:
    def __init__(self, path, params=None, http_verb="POST", headers=None):
        if headers is None:
            headers = {}

        self.path = path
        self.params = params
        self.http_verb = http_verb
        self.headers = headers
        self.params_in_query = http_verb in {"GET", "DELETE"}

    def get_params(self):
        if self.params_in_query and self.params is not None:
            return f"?{build_query_string(self.params)}"
        else:
            return truncate(f"{self.params}") if self.params is not None else ""

    def __str__(self):
        headers = self.headers or ""
        params_ = self.get_params()
        if self.params_in_query:
            params = ""
            query_params = params_
        else:
            params = params_
            query_params = ""

        return f"{self.http_verb} {self.path}{query_params} {headers} {params}"


def int_or_none(v):
    return int(v) if v is not None else None


class FakeSocket:
    def __init__(self, bs):
        self.file = BytesIO(bs)

    def makefile(self, *args, **kwargs):
        return self.file


class Response:
    """
    Response to request sent via :py:class:`ccf.clients.CCFClient`
    """

    def __init__(self, status_code, body, seqno, view, global_commit, headers):
        #: Response HTTP status code
        self.status_code = status_code
        #: Response body
        self.body = body
        #: CCF sequence number
        self.seqno = seqno
        #: CCF consensus view
        self.view = view
        #: CCF global commit sequence number (deprecated)
        self.global_commit = global_commit
        #: Response HTTP headers
        self.headers = headers

    def __str__(self):
        versioned = (self.view, self.seqno) != (None, None)
        return (
            f"{self.status_code} "
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
            status_code=rr.status_code,
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
            status_code=response.status,
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
    """
    Exception raised if a :py:class:`ccf.clients.CCFClient` instance cannot successfully establish a connection with a target CCF node.
    """


def get_curve(ca_file):
    # Auto detect EC curve to use based on server CA
    ca_bytes = open(ca_file, "rb").read()
    return (
        x509.load_pem_x509_certificate(ca_bytes, default_backend()).public_key().curve
    )


class CurlClient:
    """
    This client uses Curl to send HTTP requests to CCF, and logs all Curl commands it runs. These commands could also be run manually, or used by another client tool.
    """

    def __init__(self, host, port, ca=None, cert=None, key=None):
        self.host = host
        self.port = port
        self.ca = ca
        self.cert = cert
        self.key = key

        ca_curve = get_curve(self.ca)
        if ca_curve.name == "secp256k1":
            raise RuntimeError(
                f"CurlClient cannot perform TLS handshake with {ca_curve.name} ECDH curve. "
                "Use RequestClient class instead."
            )

    def request(self, request, signed=False, timeout=DEFAULT_REQUEST_TIMEOUT_SEC):
        with tempfile.NamedTemporaryFile() as nf:
            if signed:
                cmd = ["scurl.sh"]
            else:
                cmd = ["curl"]

            url = f"https://{self.host}:{self.port}{request.path}"

            if request.params_in_query and request.params is not None:
                url += request.get_params()

            cmd += [
                url,
                "-X",
                request.http_verb,
                "-i",
                f"-m {timeout}",
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
    """
    Support for secp256k1 as node and network identity curve.
    """

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
    """
    Support for HTTP signatures with empty body.
    """

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
    """
    CCF default client and wrapper around Python Requests, handling HTTP signatures.
    """

    def __init__(self, host, port, ca, cert=None, key=None):
        self.host = host
        self.port = port
        self.ca = ca
        self.cert = cert
        self.key = key
        self.session = requests.Session()
        self.session.verify = self.ca
        self.session.cert = (self.cert, self.key)
        self.session.mount("https://", TlsAdapter(self.ca))

    def request(self, request, signed=False, timeout=DEFAULT_REQUEST_TIMEOUT_SEC):
        extra_headers = {}
        extra_headers.update(request.headers)

        auth_value = None
        if signed:
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
                request_args["params"] = build_query_string(request.params)
            else:
                request_args["json"] = request_params

        try:
            response = self.session.request(timeout=timeout, **request_args)
        except requests.exceptions.ReadTimeout as exc:
            raise TimeoutError from exc
        except requests.exceptions.SSLError as exc:
            raise CCFConnectionException from exc
        except Exception as exc:
            raise RuntimeError("Request client failed with unexpected error") from exc

        return Response.from_requests_response(response)


class WSClient:
    """
    CCF WebSocket client implementation.

    Note: Client signatures over WebSocket are not supported by CCF.
    """

    def __init__(self, host, port, ca, cert=None, key=None):
        self.host = host
        self.port = port
        self.ca = ca
        self.cert = cert
        self.key = key
        self.ws = None

        ca_curve = get_curve(self.ca)
        if ca_curve.name == "secp256k1":
            raise RuntimeError(
                f"WSClient cannot perform TLS handshake with {ca_curve.name} ECDH curve. "
                "Use RequestClient class instead."
            )

    def request(self, request, signed=False, timeout=DEFAULT_REQUEST_TIMEOUT_SEC):
        if signed:
            raise RuntimeError(
                "Client signatures over WebSocket are not supported by CCF"
            )

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
                    timeout=timeout,
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
        (status_code,) = struct.unpack("<h", out[:2])
        (seqno,) = struct.unpack("<Q", out[2:10])
        (view,) = struct.unpack("<Q", out[10:18])
        (global_commit,) = struct.unpack("<Q", out[18:26])
        payload = out[26:]
        # TODO: move out the decoding!
        if status_code == 200:
            body = json.loads(payload) if payload else None
        else:
            body = payload.decode()
        return Response(status_code, body, seqno, view, global_commit, headers={})


class CCFClient:
    """
    Client used to connect securely and issue requests to a given CCF node.

    This is a very thin wrapper around Python Requests with TLS with added:

    - Retry logic when connecting to nodes that are joining the network
    - Support for HTTP signatures (https://tools.ietf.org/html/draft-cavage-http-signatures-12).

    Note: Experimental support for WebSocket is also available by setting the ``ws`` parameter to ``True``.

    :param str host: RPC IP address or domain name of node to connect to.
    :param int port: RPC port number of node to connect to.
    :param str ca: Path to CCF network certificate.
    :param str cert: Path to client certificate (optional).
    :param str key: Path to client private key (optional).
    :param int connection_timeout: Maximum time to wait for successful connection establishment before giving up.
    :param str description: Message to print on each request emitted with this client.
    :param bool ws: Use WebSocket client (experimental).

    A :py:exc:`CCFConnectionException` exception is raised if the connection is not established successfully within ``connection_timeout`` seconds.
    """

    def __init__(
        self,
        host,
        port,
        ca,
        cert=None,
        key=None,
        connection_timeout=DEFAULT_CONNECTION_TIMEOUT_SEC,
        description=None,
        ws=False,
    ):
        self.connection_timeout = connection_timeout
        self.description = description
        self.name = f"[{host}:{port}]"

        if os.getenv("CURL_CLIENT"):
            self.client_impl = CurlClient(host, port, ca, cert, key)
        elif os.getenv("WEBSOCKETS_CLIENT") or ws:
            self.client_impl = WSClient(host, port, ca, cert, key)
        else:
            self.client_impl = RequestClient(host, port, ca, cert, key)

    def _response(self, response):
        LOG.info(response)
        return response

    # pylint: disable=method-hidden
    def _direct_call(
        self,
        path,
        params=None,
        http_verb="POST",
        headers=None,
        signed=False,
        timeout=DEFAULT_REQUEST_TIMEOUT_SEC,
    ):
        description = ""
        if self.description:
            description = f" ({self.description})" + (" [signed]" if signed else "")

        r = Request(path, params, http_verb, headers)
        LOG.info(f"{self.name} {r} {description}")
        return self._response(self.client_impl.request(r, signed, timeout))

    def call(
        self,
        path,
        params=None,
        http_verb="POST",
        headers=None,
        signed=False,
        timeout=DEFAULT_REQUEST_TIMEOUT_SEC,
    ):
        """
        Issues one request, synchronously, and returns the response.

        :param str path: URI of the targeted resource.
        :param dict params: Request parameters (optional).
        :param http_verb: HTTP verb (e.g. "POST" or "GET").
        :param headers: HTTP request headers (optional).
        :param bool signed: Sign request with client private key.
        :param int timeout: Maximum time to wait corresponding response before giving up.

        :return: :py:class:`ccf.clients.Response`
        """
        end_time = time.time() + self.connection_timeout
        while True:
            try:
                response = self._direct_call(
                    path, params, http_verb, headers, signed, timeout
                )
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
        """
        Issue ``GET`` request.
        See :py:meth:`ccf.clients.CCFClient.call`.

        :return: :py:class:`ccf.clients.Response`
        """
        return self.call(*args, http_verb="GET", **kwargs)

    def post(self, *args, **kwargs):
        """
        Issue ``POST`` request.
        See :py:meth:`ccf.clients.CCFClient.call`.

        :return: :py:class:`ccf.clients.Response`
        """
        return self.call(*args, http_verb="POST", **kwargs)

    def put(self, *args, **kwargs):
        """
        Issue ``PUT`` request.
        See :py:meth:`ccf.clients.CCFClient.call`.

        :return: :py:class:`ccf.clients.Response`
        """
        return self.call(*args, http_verb="PUT", **kwargs)

    def delete(self, *args, **kwargs):
        """
        Issue ``DELETE`` request.
        See :py:meth:`ccf.clients.CCFClient.call`.

        :return: :py:class:`ccf.clients.Response`
        """
        return self.call(*args, http_verb="DELETE", **kwargs)

    def head(self, *args, **kwargs):
        """
        Issue ``HEAD`` request.
        See :py:meth:`ccf.clients.CCFClient.call`.

        :return: :py:class:`ccf.clients.Response`
        """
        return self.call(*args, http_verb="HEAD", **kwargs)

    def wait_for_commit(self, response, timeout=DEFAULT_COMMIT_TIMEOUT_SEC):
        """
        Given a :py:class:`ccf.clients.Response`, this functions waits
        for the associated sequence number and view to be committed by the CCF network.

        The client will poll the ``/node/tx`` endpoint until ``COMMITTED`` is returned.

        :param ccf.clients.Response response: Response returned by :py:meth:`ccf.clients.CCFClient.call`
        :param int timeout: Maximum time (secs) to wait for commit before giving up.

        A ``TimeoutError`` exception is raised if the transaction is not committed within ``timeout`` seconds.
        """
        ccf.commit.wait_for_commit(self, response.seqno, response.view, timeout)


@contextlib.contextmanager
def client(*args, **kwargs):
    yield CCFClient(*args, **kwargs)
