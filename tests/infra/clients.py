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
import hashlib
from dataclasses import dataclass
from http.client import HTTPResponse
from io import BytesIO
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import struct
import base64
import re
from typing import Union, Optional, List, Any
from ccf.tx_id import TxID

import httpx
from loguru import logger as LOG  # type: ignore

import infra.commit
from infra.log_capture import flush_info


class HttpSig(httpx.Auth):
    requires_request_body = True

    def __init__(self, key_id, pem_private_key):
        self.key_id = key_id
        self.private_key = load_pem_private_key(
            pem_private_key, password=None, backend=default_backend()
        )

    @staticmethod
    def add_signature_headers(headers, content, method, path, key_id, private_key):
        body_digest = base64.b64encode(hashlib.sha256(content).digest()).decode("ascii")
        headers["digest"] = f"SHA-256={body_digest}"
        string_to_sign = "\n".join(
            [
                f"(request-target): {method.lower()} {path}",
                f"digest: SHA-256={body_digest}",
                f"content-length: {len(content)}",
            ]
        ).encode("utf-8")
        digest_algo = {256: hashes.SHA256(), 384: hashes.SHA384()}[
            private_key.curve.key_size
        ]
        signature = private_key.sign(
            signature_algorithm=ec.ECDSA(algorithm=digest_algo), data=string_to_sign
        )
        b64signature = base64.b64encode(signature).decode("ascii")
        headers[
            "authorization"
        ] = f'Signature keyId="{key_id}",algorithm="hs2019",headers="(request-target) digest content-length",signature="{b64signature}"'

    def auth_flow(self, request):
        HttpSig.add_signature_headers(
            request.headers,
            request.content,
            request.method,
            request.url.raw_path.decode("utf-8"),
            self.key_id,
            self.private_key,
        )
        yield request


loguru_tag_regex = re.compile(r"\\?</?((?:[fb]g\s)?[^<>\s]*)>")


def escape_loguru_tags(s):
    return loguru_tag_regex.sub(lambda match: f"\\{match[0]}", s)


def truncate(string: str, max_len: int = 256):
    if len(string) > max_len:
        return f"{string[: max_len]} + {len(string) - max_len} chars"
    else:
        return string


CCF_TX_ID_HEADER = "x-ms-ccf-transaction-id"

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
    #: Whether redirect headers should be transparently followed
    allow_redirects: bool

    def __str__(self):
        string = f"<cyan>{self.http_verb}</> <green>{self.path}</>"
        if self.headers:
            string += f" <blue>{truncate(str(self.headers), max_len=25)}</>"
        if self.body is not None:
            string += f' {truncate(f"{self.body}")}'

        return string


@dataclass
class Identity:
    """
    Identity (as private key and corresponding certificate) for a :py:class:`infra.clients.CCFClient` client.
    """

    #: Path to file containing private key
    key: str
    #: Path to file containing PEM certificate
    cert: str
    #: Identity description
    description: str


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
    def __init__(self, response: httpx.Response):
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
    Response to request sent via :py:class:`infra.clients.CCFClient`
    """

    #: Response HTTP status code
    status_code: int
    #: Response body
    body: ResponseBody
    #: CCF sequence number
    seqno: Optional[int]
    #: CCF consensus view
    view: Optional[int]
    #: Response HTTP headers
    headers: dict

    def __str__(self):
        versioned = (self.view, self.seqno) != (None, None)
        status_color = "red" if self.status_code // 100 in (4, 5) else "green"
        body_s = escape_loguru_tags(truncate(str(self.body)))
        # Body can't end with a \, or it will escape the loguru closing tag
        if len(body_s) > 0 and body_s[-1] == "\\":
            body_s += " "

        return (
            f"<{status_color}>{self.status_code}</> "
            + (f"@<magenta>{self.view}.{self.seqno}</> " if versioned else "")
            + f"<yellow>{body_s}</>"
        )

    @staticmethod
    def from_requests_response(rr):
        tx_id = TxID.from_str(rr.headers.get(CCF_TX_ID_HEADER))
        return Response(
            status_code=rr.status_code,
            body=RequestsResponseBody(rr),
            seqno=tx_id.seqno,
            view=tx_id.view,
            headers=rr.headers,
        )

    @staticmethod
    def from_raw(raw):
        # Raw is the output of curl, which is a full HTTP response.
        # But in the case of a redirect, it is multiple concatenated responses.
        # We want the final response, so we keep constructing new responses from this stream until we have reached the end
        while True:
            sock = FakeSocket(raw)
            response = HTTPResponse(sock)
            response.begin()
            response_len = sock.file.tell() + response.length
            raw_len = len(raw)
            if raw_len == response_len:
                break
            raw = raw[response_len:]

        raw_body = response.read()

        tx_id = TxID.from_str(response.getheader(CCF_TX_ID_HEADER))
        return Response(
            response.status,
            body=RawResponseBody(raw_body),
            seqno=tx_id.seqno,
            view=tx_id.view,
            headers=response.headers,
        )

    @staticmethod
    def from_socket(socket):
        response = HTTPResponse(socket)
        response.begin()
        raw_body = response.read()
        tx_id = TxID.from_str(response.getheader(CCF_TX_ID_HEADER))
        return Response(
            response.status,
            body=RawResponseBody(raw_body),
            seqno=tx_id.seqno,
            view=tx_id.view,
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
    Exception raised if a :py:class:`infra.clients.CCFClient` instance cannot successfully establish
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
        self,
        host,
        port,
        ca=None,
        session_auth=None,
        signing_auth=None,
        common_headers=None,
        **kwargs,
    ):
        self.host = host
        self.port = port
        self.ca = ca
        self.session_auth = session_auth
        self.signing_auth = signing_auth
        self.ca_curve = get_curve(self.ca)

    def request(self, request, timeout=DEFAULT_REQUEST_TIMEOUT_SEC):
        with tempfile.NamedTemporaryFile() as nf:
            if self.signing_auth:
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

            if request.allow_redirects:
                cmd.append("-L")

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
                if not "content-type" in request.headers and len(request.body) > 0:
                    request.headers["content-type"] = content_type

            # Set requested headers first - so they take precedence over defaults
            for k, v in request.headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

            if self.ca:
                cmd.extend(["--cacert", self.ca])
            if self.session_auth:
                cmd.extend(["--key", self.session_auth.key])
                cmd.extend(["--cert", self.session_auth.cert])
            if self.signing_auth:
                cmd.extend(["--signing-key", self.signing_auth.key])
                cmd.extend(["--signing-cert", self.signing_auth.cert])

            cmd_s = " ".join(cmd)
            env = {k: v for k, v in os.environ.items()}

            LOG.debug(f"Running: {cmd_s}")
            rc = subprocess.run(cmd, capture_output=True, check=False, env=env)

            if rc.returncode != 0:
                if rc.returncode in [
                    35,
                    60,
                ]:  # PEER_FAILED_VERIFICATION, SSL_CONNECT_ERROR
                    raise CCFConnectionException
                if rc.returncode == 28:  # OPERATION_TIMEDOUT
                    raise TimeoutError
                LOG.error(rc.stderr)
                raise RuntimeError(f"Curl failed with return code {rc.returncode}")

            return Response.from_raw(rc.stdout)

    def close(self):
        pass


class RequestClient:
    """
    CCF default client and wrapper around Python Requests, handling HTTP signatures.
    """

    _auth_provider = HttpSig

    def __init__(
        self,
        host: str,
        port: int,
        ca: str,
        session_auth: Optional[Identity] = None,
        signing_auth: Optional[Identity] = None,
        common_headers: Optional[dict] = None,
        **kwargs,
    ):
        self.host = host
        self.port = port
        self.ca = ca
        self.session_auth = session_auth
        self.signing_auth = signing_auth
        self.common_headers = common_headers
        self.key_id = None
        cert = None
        if self.session_auth:
            cert = (self.session_auth.cert, self.session_auth.key)
        self.session = httpx.Client(verify=self.ca, cert=cert, **kwargs)
        if self.signing_auth:
            with open(self.signing_auth.cert, encoding="utf-8") as cert_file:
                self.key_id = (
                    x509.load_pem_x509_certificate(
                        cert_file.read().encode(), default_backend()
                    )
                    .fingerprint(hashes.SHA256())
                    .hex()
                )

    def request(
        self,
        request: Request,
        timeout: int = DEFAULT_REQUEST_TIMEOUT_SEC,
    ):
        extra_headers = {}
        if self.common_headers is not None:
            extra_headers.update(self.common_headers)

        extra_headers.update(request.headers)

        auth = None
        if self.signing_auth is not None:
            # Add content length of 0 when signing a GET request
            if request.http_verb == "GET":
                if (
                    "Content-Length" in extra_headers
                    and extra_headers.get("Content-Length") != "0"
                ):
                    raise ValueError(
                        "Content-Length should be set to 0 for GET requests"
                    )
                else:
                    extra_headers["Content-Length"] = "0"
            auth = self._auth_provider(
                self.key_id, open(self.signing_auth.key, "rb").read()
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

            if not "content-type" in request.headers and len(request.body) > 0:
                extra_headers["content-type"] = content_type

        try:
            response = self.session.request(
                request.http_verb,
                url=f"https://{self.host}:{self.port}{request.path}",
                auth=auth,
                headers=extra_headers,
                follow_redirects=request.allow_redirects,
                timeout=timeout,
                content=request_body,
            )
        except httpx.ReadTimeout as exc:
            raise TimeoutError from exc
        except httpx.NetworkError as exc:
            raise CCFConnectionException from exc
        except Exception as exc:
            raise RuntimeError("Request client failed with unexpected error") from exc

        return Response.from_requests_response(response)

    def close(self):
        self.session.close()


class CCFClient:
    """
    Client used to connect securely and issue requests to a given CCF node.

    This is a wrapper around either Python Requests over TLS or curl with added:

    - Retry logic when connecting to nodes that are joining the network
    - Support for HTTP signatures (https://tools.ietf.org/html/draft-cavage-http-signatures-12).

    :param str host: RPC IP address or domain name of node to connect to.
    :param int port: RPC port number of node to connect to.
    :param str ca: Path to CCF service certificate.
    :param Identity session_auth: Path to private key and certificate to be used as client authentication for the session (optional).
    :param Identity signing_auth: Path to private key and certificate to be used to sign requests for the session (optional).
    :param int connection_timeout: Maximum time to wait for successful connection establishment before giving up.
    :param str description: Message to print on each request emitted with this client.
    :param dict common_headers: Headers which should be added to every request.
    :param dict kwargs: Keyword args to be forwarded to the client implementation.

    A :py:exc:`CCFConnectionException` exception is raised if the connection is not established successfully within ``connection_timeout`` seconds.
    """

    default_impl_type: Union[CurlClient, RequestClient] = (
        CurlClient if os.getenv("CURL_CLIENT") else RequestClient
    )

    def __init__(
        self,
        host: str,
        port: int,
        ca: str,
        session_auth: Optional[Identity] = None,
        signing_auth: Optional[Identity] = None,
        connection_timeout: int = DEFAULT_CONNECTION_TIMEOUT_SEC,
        description: Optional[str] = None,
        impl_type: Union[CurlClient, RequestClient] = default_impl_type,
        common_headers: Optional[dict] = None,
        **kwargs,
    ):
        self.connection_timeout = connection_timeout
        self.hostname = f"{host}:{port}"
        self.name = f"[{self.hostname}]"
        self.description = description or self.name
        self.is_connected = False
        self.auth = bool(session_auth)
        self.sign = bool(signing_auth)

        self.client_impl = impl_type(
            host,
            port,
            ca,
            session_auth,
            signing_auth,
            common_headers,
            **kwargs,
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
        timeout: int = DEFAULT_REQUEST_TIMEOUT_SEC,
        log_capture: Optional[list] = None,
        allow_redirects=True,
    ) -> Response:
        if headers is None:
            headers = {}
        r = Request(path, body, http_verb, headers, allow_redirects)
        flush_info([f"{self.description} {r}"], log_capture, 3)
        response = self.client_impl.request(r, timeout)
        flush_info([str(response)], log_capture, 3)
        return response

    def call(
        self,
        path: str,
        body: Optional[Union[str, dict, bytes]] = None,
        http_verb: str = "POST",
        headers: Optional[dict] = None,
        timeout: int = DEFAULT_REQUEST_TIMEOUT_SEC,
        log_capture: Optional[list] = None,
        allow_redirects: bool = True,
    ) -> Response:
        """
        Issues one request, synchronously, and returns the response.

        :param str path: URI of the targeted resource. Must begin with '/'
        :param body: Request body (optional).
        :type body: str or dict or bytes
        :param str http_verb: HTTP verb (e.g. "POST" or "GET").
        :param dict headers: HTTP request headers (optional).
        :param int timeout: Maximum time to wait for a response before giving up.
        :param list log_capture: Rather than emit to default handler, capture log lines to list (optional).
        :param bool allow_redirects: Select whether redirects are followed.

        :return: :py:class:`infra.clients.Response`
        """
        if not path.startswith("/"):
            raise ValueError(f"URL path '{path}' is invalid, must start with /")

        logs: List[str] = []

        if self.is_connected:
            r = self._call(
                path, body, http_verb, headers, timeout, logs, allow_redirects
            )
            flush_info(logs, log_capture, 2)
            return r

        end_time = time.time() + self.connection_timeout
        while True:
            try:
                logs = []
                response = self._call(
                    path, body, http_verb, headers, timeout, logs, allow_redirects
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
        See :py:meth:`infra.clients.CCFClient.call`.

        :return: :py:class:`infra.clients.Response`
        """
        if "http_verb" in kwargs:
            raise ValueError('"http_verb" should not be specified')

        kwargs["http_verb"] = "GET"
        return self.call(*args, **kwargs)

    def post(self, *args, **kwargs) -> Response:
        """
        Issue ``POST`` request.
        See :py:meth:`infra.clients.CCFClient.call`.

        :return: :py:class:`infra.clients.Response`
        """
        if "http_verb" in kwargs:
            raise ValueError('"http_verb" should not be specified')

        kwargs["http_verb"] = "POST"
        return self.call(*args, **kwargs)

    def put(self, *args, **kwargs) -> Response:
        """
        Issue ``PUT`` request.
        See :py:meth:`infra.clients.CCFClient.call`.

        :return: :py:class:`infra.clients.Response`
        """
        if "http_verb" in kwargs:
            raise ValueError('"http_verb" should not be specified')

        kwargs["http_verb"] = "PUT"
        return self.call(*args, **kwargs)

    def delete(self, *args, **kwargs) -> Response:
        """
        Issue ``DELETE`` request.
        See :py:meth:`infra.clients.CCFClient.call`.

        :return: :py:class:`infra.clients.Response`
        """
        if "http_verb" in kwargs:
            raise ValueError('"http_verb" should not be specified')

        kwargs["http_verb"] = "DELETE"
        return self.call(*args, **kwargs)

    def head(self, *args, **kwargs) -> Response:
        """
        Issue ``HEAD`` request.
        See :py:meth:`infra.clients.CCFClient.call`.

        :return: :py:class:`infra.clients.Response`
        """
        if "http_verb" in kwargs:
            raise ValueError('"http_verb" should not be specified')

        kwargs["http_verb"] = "HEAD"
        return self.call(*args, **kwargs)

    def options(self, *args, **kwargs) -> Response:
        """
        Issue ``OPTIONS`` request.
        See :py:meth:`infra.clients.CCFClient.call`.

        :return: :py:class:`infra.clients.Response`
        """
        if "http_verb" in kwargs:
            raise ValueError('"http_verb" should not be specified')

        kwargs["http_verb"] = "OPTIONS"
        return self.call(*args, **kwargs)

    def wait_for_commit(
        self, response: Response, timeout: int = DEFAULT_COMMIT_TIMEOUT_SEC
    ):
        """
        Given a :py:class:`infra.clients.Response`, this functions waits
        for the associated sequence number and view to be committed by the CCF network.

        The client will poll the ``/node/tx`` endpoint until ``COMMITTED`` is returned.

        :param infra.clients.Response response: Response returned by :py:meth:`infra.clients.CCFClient.call`
        :param int timeout: Maximum time (secs) to wait for commit before giving up.

        A ``TimeoutError`` exception is raised if the transaction is not committed within ``timeout`` seconds.
        """
        if response.seqno is None or response.view is None:
            raise ValueError(f"Response seqno and view should not be None: {response}")

        infra.commit.wait_for_commit(self, response.seqno, response.view, timeout)

    def close(self):
        self.client_impl.close()


@contextlib.contextmanager
def client(*args, **kwargs):
    c = CCFClient(*args, **kwargs)
    yield c
    c.close()
