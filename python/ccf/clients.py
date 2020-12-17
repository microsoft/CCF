# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import abc
import contextlib
import json
import time
import sys
import os
import subprocess
import tempfile
from dataclasses import dataclass
from http.client import HTTPResponse
from io import BytesIO
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context  # type: ignore
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import struct
import base64
import re
import hashlib
from typing import Union, Optional, List, Any

import requests
from loguru import logger as LOG  # type: ignore
from requests_http_signature import HTTPSignatureAuth  # type: ignore
import websocket  # type: ignore

import ccf.commit
from ccf.log_capture import flush_info


loguru_tag_regex = re.compile(r"\\?</?((?:[fb]g\s)?[^<>\s]*)>")


def escape_loguru_tags(s):
    return loguru_tag_regex.sub(lambda match: f"\\{match[0]}", s)


def truncate(string: str, max_len: int = 128):
    if len(string) > max_len:
        return f"{string[: max_len]} + {len(string) - max_len} chars"
    else:
        return string


CCF_TX_SEQNO_HEADER = "x-ccf-tx-seqno"
CCF_TX_VIEW_HEADER = "x-ccf-tx-view"
# Deprecated, will be removed
CCF_GLOBAL_COMMIT_HEADER = "x-ccf-global-commit"

DEFAULT_CONNECTION_TIMEOUT_SEC = 3
DEFAULT_REQUEST_TIMEOUT_SEC = 10
DEFAULT_COMMIT_TIMEOUT_SEC = 3

CONTENT_TYPE_TEXT = "text/plain"
CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_BINARY = "application/octet-stream"


@dataclass
class Request:
    #: Resource path (with optional query string)
    path: str
    #: Body of request
    body: Optional[Union[dict, str, bytes]]
    #: HTTP verb
    http_verb: str
    #: HTTP headers
    headers: dict

    def __str__(self):
        string = f"<cyan>{self.http_verb}</> <green>{self.path}</>"
        if self.headers:
            string += f" {self.headers}"
        if self.body is not None:
            string += f' {truncate(f"{self.body}")}'

        return string


def int_or_none(v):
    return int(v) if v is not None else None


class FakeSocket:
    def __init__(self, bs):
        self.file = BytesIO(bs)

    def makefile(self, *args, **kwargs):
        return self.file


class ResponseBody(abc.ABC):
    @abc.abstractmethod
    def data(self) -> bytes:
        pass

    @abc.abstractmethod
    def text(self) -> str:
        pass

    @abc.abstractmethod
    def json(self) -> Any:
        pass

    def __len__(self):
        return len(self.data())

    def __str__(self):
        try:
            return self.text()
        except UnicodeDecodeError:
            return self.__repr__()

    def __repr__(self):
        return repr(self.data())


class RequestsResponseBody(ResponseBody):
    def __init__(self, response: requests.Response):
        self._response = response

    def data(self):
        return self._response.content

    def text(self):
        return self._response.text

    def json(self):
        return self._response.json()


class RawResponseBody(ResponseBody):
    def __init__(self, data: bytes):
        self._data = data

    def data(self):
        return self._data

    def text(self):
        return self._data.decode()

    def json(self):
        return json.loads(self._data)


@dataclass
class Response:
    """
    Response to request sent via :py:class:`ccf.clients.CCFClient`
    """

    #: Response HTTP status code
    status_code: int
    #: Response body
    body: ResponseBody
    #: CCF sequence number
    seqno: Optional[int]
    #: CCF consensus view
    view: Optional[int]
    #: CCF global commit sequence number (deprecated)
    global_commit: Optional[int]
    #: Response HTTP headers
    headers: dict

    def __str__(self):
        versioned = (self.view, self.seqno) != (None, None)
        status_color = "red" if self.status_code / 100 in (4, 5) else "green"
        return (
            f"<{status_color}>{self.status_code}</> "
            + (f"@<magenta>{self.view}.{self.seqno}</> " if versioned else "")
            + f"<yellow>{escape_loguru_tags(truncate(str(self.body)))}</>"
        )

    @staticmethod
    def from_requests_response(rr):
        return Response(
            status_code=rr.status_code,
            body=RequestsResponseBody(rr),
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

        return Response(
            response.status,
            body=RawResponseBody(raw_body),
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
    Exception raised if a :py:class:`ccf.clients.CCFClient` instance cannot successfully establish
    a connection with a target CCF node.
    """


def get_curve(ca_file):
    # Auto detect EC curve to use based on server CA
    ca_bytes = open(ca_file, "rb").read()
    return (
        x509.load_pem_x509_certificate(ca_bytes, default_backend()).public_key().curve
    )


def unpack_seqno_or_view(data):
    (value,) = struct.unpack("<q", data)
    if value == -sys.maxsize - 1:
        return None
    return value


class CurlClient:
    """
    This client uses Curl to send HTTP requests to CCF, and logs all Curl commands it runs.
    These commands could also be run manually, or used by another client tool.
    """

    def __init__(
        self, host, port, ca=None, cert=None, key=None, disable_client_auth=False
    ):
        self.host = host
        self.port = port
        self.ca = ca
        self.cert = cert
        self.key = key
        self.disable_client_auth = disable_client_auth

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

            cmd += [
                url,
                "-X",
                request.http_verb,
                "-i",
                f"-m {timeout}",
            ]

            if request.body is not None:
                if isinstance(request.body, str) and request.body.startswith("@"):
                    # Request is already a file path - pass it directly
                    cmd.extend(["--data-binary", request.body])
                    if request.body.lower().endswith(".json"):
                        content_type = CONTENT_TYPE_JSON
                    else:
                        content_type = CONTENT_TYPE_BINARY
                else:
                    # Write request body to temp file
                    if isinstance(request.body, str):
                        msg_bytes = request.body.encode()
                        content_type = CONTENT_TYPE_TEXT
                    elif isinstance(request.body, bytes):
                        msg_bytes = request.body
                        content_type = CONTENT_TYPE_BINARY
                    else:
                        msg_bytes = json.dumps(request.body).encode()
                        content_type = CONTENT_TYPE_JSON
                    LOG.debug(f"Writing request body: {truncate(msg_bytes)}")
                    nf.write(msg_bytes)
                    nf.flush()
                    cmd.extend(["--data-binary", f"@{nf.name}"])
                if not "content-type" in request.headers:
                    request.headers["content-type"] = content_type

            # Set requested headers first - so they take precedence over defaults
            for k, v in request.headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

            if self.ca:
                cmd.extend(["--cacert", self.ca])
            if self.key:
                cmd.extend(["--key", self.key])
            if self.cert:
                cmd.extend(["--cert", self.cert])

            cmd_s = " ".join(cmd)
            env = {k: v for k, v in os.environ.items()}
            if self.disable_client_auth:
                env["DISABLE_CLIENT_AUTH"] = "1"
                cmd_s = f"DISABLE_CLIENT_AUTH=1 {cmd_s}"

            LOG.debug(f"Running: {cmd_s}")
            rc = subprocess.run(cmd, capture_output=True, check=False, env=env)

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

    def __init__(
        self,
        host: str,
        port: int,
        ca: str,
        cert: Optional[str] = None,
        key: Optional[str] = None,
        disable_client_auth: bool = False,
        key_id: Optional[int] = False,
    ):
        self.host = host
        self.port = port
        self.ca = ca
        self.cert = cert
        self.key = key
        self.key_id = None
        self.session = requests.Session()
        self.session.verify = self.ca
        if (self.cert is not None and self.key is not None) and not disable_client_auth:
            self.session.cert = (self.cert, self.key)
        if self.cert:
            with open(self.cert) as cert_file:
                self.key_id = hashlib.sha256(cert_file.read().encode()).hexdigest()
        self.session.mount("https://", TlsAdapter(self.ca))

    def request(
        self,
        request: Request,
        signed: bool = False,
        timeout: int = DEFAULT_REQUEST_TIMEOUT_SEC,
    ):
        extra_headers = {}
        extra_headers.update(request.headers)

        auth_value = None
        if signed:
            if self.key is None:
                raise ValueError("Cannot sign request if client has no key")

            auth_value = HTTPSignatureAuth_AlwaysDigest(
                algorithm="ecdsa-sha256",
                key=open(self.key, "rb").read(),
                key_id=self.key_id,
                headers=["(request-target)", "Digest", "Content-Length"],
            )

        request_body = None
        if request.body is not None:
            if isinstance(request.body, str) and request.body.startswith("@"):
                # Request is a file path - read contents
                with open(request.body[1:], "rb") as f:
                    request_body = f.read()
                if request.body.lower().endswith(".json"):
                    content_type = CONTENT_TYPE_JSON
                else:
                    content_type = CONTENT_TYPE_BINARY
            elif isinstance(request.body, str):
                request_body = request.body.encode()
                content_type = CONTENT_TYPE_TEXT
            elif isinstance(request.body, bytes):
                request_body = request.body
                content_type = CONTENT_TYPE_BINARY
            else:
                request_body = json.dumps(request.body).encode()
                content_type = CONTENT_TYPE_JSON

            if not "content-type" in request.headers:
                extra_headers["content-type"] = content_type

        try:
            response = self.session.request(
                request.http_verb,
                url=f"https://{self.host}:{self.port}{request.path}",
                auth=auth_value,
                headers=extra_headers,
                allow_redirects=False,
                timeout=timeout,
                data=request_body,
            )
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

    def __init__(
        self,
        host: str,
        port: int,
        ca: str,
        cert: Optional[str] = None,
        key: Optional[str] = None,
        disable_client_auth: bool = False,
    ):
        self.host = host
        self.port = port
        self.ca = ca
        self.cert = cert
        self.key = key
        self.ws = None
        self.disable_client_auth = disable_client_auth

        ca_curve = get_curve(self.ca)
        if ca_curve.name == "secp256k1":
            raise RuntimeError(
                f"WSClient cannot perform TLS handshake with {ca_curve.name} ECDH curve. "
                "Use RequestClient class instead."
            )

    def request(
        self,
        request: Request,
        signed: bool = False,
        timeout: int = DEFAULT_REQUEST_TIMEOUT_SEC,
    ):
        if signed:
            raise ValueError(
                "Client signatures over WebSocket are not supported by CCF"
            )

        if self.ws is None:
            LOG.info("Creating WSS connection")
            try:
                self.ws = websocket.create_connection(
                    f"wss://{self.host}:{self.port}",
                    sslopt={
                        "certfile": self.cert if not self.disable_client_auth else None,
                        "keyfile": self.key if not self.disable_client_auth else None,
                        "ca_certs": self.ca,
                    },
                    timeout=timeout,
                )
            except Exception as exc:
                raise CCFConnectionException from exc

        assert self.ws is not None

        if isinstance(request.body, str):
            payload = request.body.encode()
        elif isinstance(request.body, bytes):
            payload = request.body
        else:
            payload = json.dumps(request.body).encode()
        path = (request.path).encode()
        header = struct.pack("<h", len(path)) + path
        # FIN, no RSV, BIN, UNMASKED every time, because it's all we support right now
        frame = websocket.ABNF(
            1, 0, 0, 0, websocket.ABNF.OPCODE_BINARY, 0, header + payload
        )
        self.ws.send_frame(frame)
        out = self.ws.recv_frame().data
        (status_code,) = struct.unpack("<h", out[:2])
        seqno = unpack_seqno_or_view(out[2:10])
        view = unpack_seqno_or_view(out[10:18])
        global_commit = unpack_seqno_or_view(out[18:26])
        payload = out[26:]
        body = RawResponseBody(payload)
        return Response(status_code, body, seqno, view, global_commit, headers={})


class CCFClient:
    """
    Client used to connect securely and issue requests to a given CCF node.

    This is a wrapper around either Python Requests, curl or a websockets client over TLS with added:

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
    :param bool disable_client_auth: Do not use the provided client identity to authenticate. The client identity will still be used to sign if ``signed`` is set to True when making requests.

    A :py:exc:`CCFConnectionException` exception is raised if the connection is not established successfully within ``connection_timeout`` seconds.
    """

    client_impl: Union[CurlClient, WSClient, RequestClient]

    def __init__(
        self,
        host: str,
        port: int,
        ca: str,
        cert: Optional[str] = None,
        key: Optional[str] = None,
        connection_timeout: int = DEFAULT_CONNECTION_TIMEOUT_SEC,
        description: Optional[str] = None,
        ws: bool = False,
        disable_client_auth: bool = False,
    ):
        self.connection_timeout = connection_timeout
        self.description = description
        self.name = f"[{host}:{port}]"
        self.is_connected = False

        if os.getenv("CURL_CLIENT"):
            self.client_impl = CurlClient(
                host, port, ca, cert, key, disable_client_auth
            )
        elif os.getenv("WEBSOCKETS_CLIENT") or ws:
            self.client_impl = WSClient(host, port, ca, cert, key, disable_client_auth)
        else:
            self.client_impl = RequestClient(
                host, port, ca, cert, key, disable_client_auth
            )

    def _response(self, response: Response) -> Response:
        LOG.info(response)
        return response

    def _call(
        self,
        path: str,
        body: Optional[Union[str, dict, bytes]] = None,
        http_verb: str = "POST",
        headers: Optional[dict] = None,
        signed: bool = False,
        timeout: int = DEFAULT_REQUEST_TIMEOUT_SEC,
        log_capture: Optional[list] = None,
    ) -> Response:
        description = ""
        if self.description:
            description = f"{self.description}{signed * 's'}"
        else:
            description = self.name

        if headers is None:
            headers = {}
        r = Request(path, body, http_verb, headers)

        flush_info([f"{description} {r}"], log_capture, 3)
        response = self.client_impl.request(r, signed, timeout)
        flush_info([str(response)], log_capture, 3)
        return response

    def call(
        self,
        path: str,
        body: Optional[Union[str, dict, bytes]] = None,
        http_verb: str = "POST",
        headers: Optional[dict] = None,
        signed: bool = False,
        timeout: int = DEFAULT_REQUEST_TIMEOUT_SEC,
        log_capture: Optional[list] = None,
    ) -> Response:
        """
        Issues one request, synchronously, and returns the response.

        :param str path: URI of the targeted resource. Must begin with '/'
        :param body: Request body (optional).
        :type body: str or dict or bytes
        :param str http_verb: HTTP verb (e.g. "POST" or "GET").
        :param dict headers: HTTP request headers (optional).
        :param bool signed: Sign request with client private key.
        :param int timeout: Maximum time to wait for a response before giving up.
        :param list log_capture: Rather than emit to default handler, capture log lines to list (optional).

        :return: :py:class:`ccf.clients.Response`
        """
        if not path.startswith("/"):
            raise ValueError(f"URL path '{path}' is invalid, must start with /")

        logs: List[str] = []

        if self.is_connected:
            r = self._call(path, body, http_verb, headers, signed, timeout, logs)
            flush_info(logs, log_capture, 2)
            return r

        end_time = time.time() + self.connection_timeout
        while True:
            try:
                logs = []
                response = self._call(
                    path, body, http_verb, headers, signed, timeout, logs
                )
                # Only the first request gets this timeout logic - future calls
                # call _call
                self.is_connected = True
                flush_info(logs, log_capture, 2)
                return response
            except (CCFConnectionException, TimeoutError) as e:
                # If the initial connection fails (e.g. due to node certificate
                # not yet being endorsed by the network) sleep briefly and try again
                if time.time() > end_time:
                    flush_info(logs, log_capture, 2)
                    raise CCFConnectionException(
                        f"Connection still failing after {self.connection_timeout}s"
                    ) from e
                time.sleep(0.1)

    def get(self, *args, **kwargs) -> Response:
        """
        Issue ``GET`` request.
        See :py:meth:`ccf.clients.CCFClient.call`.

        :return: :py:class:`ccf.clients.Response`
        """
        if "http_verb" in kwargs:
            raise ValueError('"http_verb" should not be specified')

        kwargs["http_verb"] = "GET"
        return self.call(*args, **kwargs)

    def post(self, *args, **kwargs) -> Response:
        """
        Issue ``POST`` request.
        See :py:meth:`ccf.clients.CCFClient.call`.

        :return: :py:class:`ccf.clients.Response`
        """
        if "http_verb" in kwargs:
            raise ValueError('"http_verb" should not be specified')

        kwargs["http_verb"] = "POST"
        return self.call(*args, **kwargs)

    def put(self, *args, **kwargs) -> Response:
        """
        Issue ``PUT`` request.
        See :py:meth:`ccf.clients.CCFClient.call`.

        :return: :py:class:`ccf.clients.Response`
        """
        if "http_verb" in kwargs:
            raise ValueError('"http_verb" should not be specified')

        kwargs["http_verb"] = "PUT"
        return self.call(*args, **kwargs)

    def delete(self, *args, **kwargs) -> Response:
        """
        Issue ``DELETE`` request.
        See :py:meth:`ccf.clients.CCFClient.call`.

        :return: :py:class:`ccf.clients.Response`
        """
        if "http_verb" in kwargs:
            raise ValueError('"http_verb" should not be specified')

        kwargs["http_verb"] = "DELETE"
        return self.call(*args, **kwargs)

    def head(self, *args, **kwargs) -> Response:
        """
        Issue ``HEAD`` request.
        See :py:meth:`ccf.clients.CCFClient.call`.

        :return: :py:class:`ccf.clients.Response`
        """
        if "http_verb" in kwargs:
            raise ValueError('"http_verb" should not be specified')

        kwargs["http_verb"] = "HEAD"
        return self.call(*args, **kwargs)

    def wait_for_commit(
        self, response: Response, timeout: int = DEFAULT_COMMIT_TIMEOUT_SEC
    ):
        """
        Given a :py:class:`ccf.clients.Response`, this functions waits
        for the associated sequence number and view to be committed by the CCF network.

        The client will poll the ``/node/tx`` endpoint until ``COMMITTED`` is returned.

        :param ccf.clients.Response response: Response returned by :py:meth:`ccf.clients.CCFClient.call`
        :param int timeout: Maximum time (secs) to wait for commit before giving up.

        A ``TimeoutError`` exception is raised if the transaction is not committed within ``timeout`` seconds.
        """
        if response.seqno is None or response.view is None:
            raise ValueError("Response seqno and view should not be None")

        ccf.commit.wait_for_commit(self, response.seqno, response.view, timeout)


@contextlib.contextmanager
def client(*args, **kwargs):
    yield CCFClient(*args, **kwargs)
