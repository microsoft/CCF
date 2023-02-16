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
from datetime import datetime
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
import ssl
import socket
import urllib.parse

import httpx
from loguru import logger as LOG  # type: ignore

import infra.commit
from infra.log_capture import flush_info
import ccf.cose


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
CONTENT_TYPE_COSE = "application/cose"


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
            # This may contain a stringified HTTP/2 response, which HTTPResponse can't parse.
            # Replace the HTTP version in the status line in this case - we don't care what version it parses.
            if raw.startswith(b"HTTP/2"):
                raw = raw.replace(b"HTTP/2", b"HTTP/1.1", 1)
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


class CCFIOException(Exception):
    """
    Exception raised if a :py:class:`infra.clients.CCFClient` instance experiences a fatal error when
    trying to read or write from an existing connection with a target CCF node.
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


def cose_protected_headers(request_path, created_at=None):
    phdr = {"ccf.gov.msg.created_at": created_at or int(datetime.now().timestamp())}
    if request_path.endswith("gov/ack/update_state_digest"):
        phdr["ccf.gov.msg.type"] = "state_digest"
    elif request_path.endswith("gov/ack"):
        phdr["ccf.gov.msg.type"] = "ack"
    elif request_path.endswith("gov/proposals"):
        phdr["ccf.gov.msg.type"] = "proposal"
    elif request_path.endswith("/ballots"):
        pid = request_path.split("/")[-2]
        phdr["ccf.gov.msg.type"] = "ballot"
        phdr["ccf.gov.msg.proposal_id"] = pid
    elif request_path.endswith("/withdraw"):
        pid = request_path.split("/")[-2]
        phdr["ccf.gov.msg.type"] = "withdrawal"
        phdr["ccf.gov.msg.proposal_id"] = pid
    LOG.info(phdr)
    return phdr


class CurlClient:
    """
    This client uses Curl to send HTTP requests to CCF, and logs all Curl commands it runs.
    These commands could also be run manually, or used by another client tool.
    """

    created_at_override = None

    def __init__(
        self,
        hostname,
        ca=None,
        session_auth=None,
        signing_auth=None,
        cose_signing_auth=None,
        common_headers=None,
        **kwargs,
    ):
        self.hostname = hostname
        self.ca = ca
        self.session_auth = session_auth
        self.signing_auth = signing_auth
        self.cose_signing_auth = cose_signing_auth
        if os.getenv("CURL_CLIENT_USE_COSE"):
            self.cose_signing_auth = self.signing_auth
            self.signing_auth = None
        self.common_headers = common_headers or {}
        self.ca_curve = get_curve(self.ca)
        self.protocol = kwargs.get("protocol") if "protocol" in kwargs else "https"
        self.extra_args = []
        if kwargs.get("http2"):
            self.extra_args.append("--http2")

    def request(
        self,
        request: Request,
        timeout: int = DEFAULT_REQUEST_TIMEOUT_SEC,
        cose_header_parameters_override=None,
    ):
        with tempfile.NamedTemporaryFile() as nf:
            if self.signing_auth:
                cmd = ["scurl.sh"]
            else:
                cmd = ["curl"]

            url = f"{self.protocol}://{self.hostname}{request.path}"

            cmd += [url, "-X", request.http_verb, "-i", f"-m {timeout}"]

            if request.allow_redirects:
                cmd.append("-L")

            headers = {}
            if self.common_headers is not None:
                headers.update(self.common_headers)

            headers.update(request.headers)

            content_path = None

            if request.body is not None:
                if isinstance(request.body, str) and request.body.startswith("@"):
                    # Request is already a file path - pass it directly
                    content_path = request.body
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
                    content_path = f"@{nf.name}"
                if not "content-type" in headers and len(request.body) > 0:
                    headers["content-type"] = content_type

            if self.signing_auth:
                cmd = ["scurl.sh"]
            else:
                cmd = ["curl"]

            if self.cose_signing_auth:
                pre_cmd = ["ccf_cose_sign1"]
                phdr = cose_protected_headers(request.path, self.created_at_override)
                phdr.update(cose_header_parameters_override or {})
                pre_cmd.extend(["--ccf-gov-msg-type", phdr["ccf.gov.msg.type"]])
                created_at = datetime.utcfromtimestamp(phdr["ccf.gov.msg.created_at"])
                pre_cmd.extend(["--ccf-gov-msg-created_at", created_at.isoformat()])
                if "ccf.gov.msg.proposal_id" in phdr:
                    pre_cmd.extend(
                        ["--ccf-gov-msg-proposal_id", phdr["ccf.gov.msg.proposal_id"]]
                    )
                pre_cmd.extend(["--signing-key", self.cose_signing_auth.key])
                pre_cmd.extend(["--signing-cert", self.cose_signing_auth.cert])
                pre_cmd.extend(["--content", content_path.strip("@")])
                headers["content-type"] = CONTENT_TYPE_COSE

            url = f"{self.protocol}://{self.hostname}{request.path}"

            cmd += [url, "-X", request.http_verb, "-i", f"-m {timeout}"]

            if request.allow_redirects:
                cmd.append("-L")

            if request.body is not None:
                if self.cose_signing_auth:
                    cmd.extend(["--data-binary", "@-"])
                else:
                    cmd.extend(["--data-binary", content_path])

            # Set requested headers first - so they take precedence over defaults
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

            if self.ca:
                cmd.extend(["--cacert", self.ca])
            if self.session_auth:
                cmd.extend(["--key", self.session_auth.key])
                cmd.extend(["--cert", self.session_auth.cert])
            if self.signing_auth:
                cmd.extend(["--signing-key", self.signing_auth.key])
                cmd.extend(["--signing-cert", self.signing_auth.cert])

            for arg in self.extra_args:
                cmd.append(arg)

            cmd_s = " ".join(cmd)
            env = {k: v for k, v in os.environ.items()}

            if self.cose_signing_auth:
                pre_cmd_s = " ".join(pre_cmd)
                LOG.debug(f"Running: {pre_cmd_s} | {cmd_s}")
                pre_sub = subprocess.Popen(pre_cmd, stdout=subprocess.PIPE)
                rc = subprocess.run(
                    cmd, capture_output=True, check=False, env=env, stdin=pre_sub.stdout
                )
                pre_sub.wait()
            else:
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

    @staticmethod
    def extra_headers_count(http2=False):
        # curl inserts the following headers in every request
        if http2:
            #  :method: GET/POST
            #  :authority: <address>
            #  :scheme: https
            #  :path: /path
            #  accept: */*
            #  user-agent: curl/<version>
            return 6
        else:
            #  host: <address>
            #  user-agent: curl/<version>
            #  accept: */*
            return 3


class HttpxClient:
    """
    CCF default client and wrapper around Python httpx, handling HTTP signatures.
    """

    _auth_provider = HttpSig
    created_at_override = None

    def __init__(
        self,
        hostname: str,
        ca: str,
        session_auth: Optional[Identity] = None,
        signing_auth: Optional[Identity] = None,
        cose_signing_auth: Optional[Identity] = None,
        common_headers: Optional[dict] = None,
        **kwargs,
    ):
        self.hostname = hostname
        self.ca = ca
        self.session_auth = session_auth
        self.signing_auth = signing_auth
        self.cose_signing_auth = cose_signing_auth
        self.common_headers = common_headers
        self.key_id = None
        cert = None
        if self.session_auth:
            cert = (self.session_auth.cert, self.session_auth.key)
        self.protocol = "https"
        if "protocol" in kwargs:
            self.protocol = kwargs.get("protocol")
            kwargs.pop("protocol")
        self.session = httpx.Client(verify=self.ca, cert=cert, **kwargs)
        sig_auth = signing_auth or cose_signing_auth
        if sig_auth:
            with open(sig_auth.cert, encoding="utf-8") as cert_file:
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
        cose_header_parameters_override=None,
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

        if self.cose_signing_auth is not None:
            key = open(self.cose_signing_auth.key, encoding="utf-8").read()
            cert = open(self.cose_signing_auth.cert, encoding="utf-8").read()
            phdr = cose_protected_headers(request.path, self.created_at_override)
            phdr.update(cose_header_parameters_override or {})
            request_body = ccf.cose.create_cose_sign1(
                request_body or b"", key, cert, phdr
            )

            extra_headers["content-type"] = CONTENT_TYPE_COSE

        try:
            response = self.session.request(
                request.http_verb,
                url=f"{self.protocol}://{self.hostname}{request.path}",
                auth=auth,
                headers=extra_headers,
                follow_redirects=request.allow_redirects,
                timeout=timeout,
                content=request_body,
            )
        except httpx.TimeoutException as exc:
            raise TimeoutError from exc
        except httpx.ConnectError as exc:
            raise CCFConnectionException from exc
        except (httpx.WriteError, httpx.ReadError, httpx.RemoteProtocolError) as exc:
            raise CCFIOException from exc
        except Exception as exc:
            raise RuntimeError(
                f"HttpxClient failed with unexpected error: {exc}"
            ) from exc

        return Response.from_requests_response(response)

    def close(self):
        self.session.close()

    @staticmethod
    def extra_headers_count(http2=False):
        # httpx inserts the following headers in every request
        if http2:
            #  :method: GET/POST
            #  :authority: <address>
            #  :scheme: https
            #  :path: /path
            #  accept: */*
            #  accept-encoding: gzip, deflate, br
            #  user-agent: python-httpx/<version>
            return 7
        else:
            #  host: <address>
            #  accept: */*
            #  accept-encoding: gzip, deflate, br
            #  connection: keep-alive
            #  user-agent: python-httpx/<version>
            return 5


class RawSocketClient:
    """
    This client wraps a single SSL socket, and reports errors if the TCP or SSL layers fail.
    """

    def __init__(
        self,
        netloc: str,
        ca: str,
        session_auth: Optional[Identity] = None,
        signing_auth: Optional[Identity] = None,
        cose_signing_auth: Optional[Identity] = None,
        common_headers: Optional[dict] = None,
        **kwargs,
    ):
        self.ca = ca
        self.session_auth = session_auth
        self.common_headers = common_headers

        if signing_auth:
            with open(signing_auth.cert, encoding="utf-8") as cert_file:
                key_id = (
                    x509.load_pem_x509_certificate(
                        cert_file.read().encode(), default_backend()
                    )
                    .fingerprint(hashes.SHA256())
                    .hex()
                )
                private_key = load_pem_private_key(
                    open(signing_auth.key, "rb").read(),
                    password=None,
                    backend=default_backend(),
                )
                self.signing_details = (key_id, private_key)
        else:
            self.signing_details = None

        hostname, port = infra.interfaces.split_netloc(netloc)

        self.socket = RawSocketClient._create_socket(
            hostname,
            port,
            self.ca,
            self.session_auth,
        )

    @staticmethod
    def _create_socket(hostname, port, ca, session_auth):
        end_time = time.time() + DEFAULT_CONNECTION_TIMEOUT_SEC
        while True:
            try:
                context = ssl.create_default_context(cafile=ca)
                if session_auth is not None:
                    context.load_cert_chain(
                        certfile=session_auth.cert,
                        keyfile=session_auth.key,
                    )

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ssl_socket = context.wrap_socket(
                    sock, server_side=False, server_hostname=hostname
                )
                ssl_socket.connect((hostname, port))
                return ssl_socket
            except (ssl.SSLEOFError, ConnectionResetError) as exc:
                if time.time() > end_time:
                    raise CCFConnectionException(
                        "Timed out connecting to node"
                    ) from exc
                else:
                    # If the initial connection fails (e.g. due to node certificate
                    # not yet being endorsed by the network) sleep briefly and try again
                    time.sleep(0.1)

    @staticmethod
    def _send_request(
        ssl_socket,
        verb,
        path,
        headers,
        content,
    ):
        data = f"{verb} {path} HTTP/1.1\r\n".encode("ascii")
        for k, v in headers.items():
            data += f"{k}: {v}\r\n".encode("ascii")

        data += b"\r\n"
        if content is not None:
            data += content

        ssl_socket.sendall(data)

    def request(
        self,
        request: Request,
        timeout: int = DEFAULT_REQUEST_TIMEOUT_SEC,
    ):
        extra_headers = {}
        if self.common_headers is not None:
            extra_headers.update(self.common_headers)

        extra_headers.update(request.headers)

        request_body = None
        content_length = 0
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
            content_length = len(request_body)

            if not "content-type" in request.headers and len(request.body) > 0:
                extra_headers["content-type"] = content_type

        if not "content-length" in extra_headers:
            extra_headers["content-length"] = content_length

        if self.signing_details is not None:
            HttpSig.add_signature_headers(
                extra_headers,
                request_body or b"",
                request.http_verb,
                request.path,
                key_id=self.signing_details[0],
                private_key=self.signing_details[1],
            )

        self.socket.settimeout(timeout)
        RawSocketClient._send_request(
            ssl_socket=self.socket,
            verb=request.http_verb,
            path=request.path,
            headers=extra_headers,
            content=request_body,
        )

        response = Response.from_socket(self.socket)
        while response.status_code == 308 and request.allow_redirects:
            assert (
                self.signing_details is None
            ), f"Received redirect response from {request.path}, but submitted signed request. Combination of signed requests and forwarding is currently unsupported"

            # Create a temporary socket to follow this redirect
            redirect_url = response.headers["location"]
            LOG.trace(f"Following redirect to: {redirect_url}")
            parsed = urllib.parse.urlparse(redirect_url)
            with RawSocketClient._create_socket(
                parsed.hostname,
                parsed.port,
                self.ca,
                self.session_auth,
            ) as redirect_socket:
                redirect_socket.settimeout(timeout)
                RawSocketClient._send_request(
                    ssl_socket=redirect_socket,
                    verb=request.http_verb,
                    path=parsed.path,
                    headers=extra_headers,
                    content=request_body,
                )
                response = Response.from_socket(redirect_socket)

        return response

    def close(self):
        self.socket.close()

    @staticmethod
    def extra_headers_count():
        # This client always inserts a content-length header
        return 1


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

    default_impl_type = (
        CurlClient
        if os.getenv("CURL_CLIENT")
        else RawSocketClient
        if os.getenv("SOCKET_CLIENT")
        else HttpxClient
    )

    def set_created_at_override(self, value):
        self.client_impl.created_at_override = value

    def __init__(
        self,
        host: str,
        port: int,
        ca: str,
        session_auth: Optional[Identity] = None,
        signing_auth: Optional[Identity] = None,
        cose_signing_auth: Optional[Identity] = None,
        connection_timeout: int = DEFAULT_CONNECTION_TIMEOUT_SEC,
        description: Optional[str] = None,
        impl_type: Union[CurlClient, HttpxClient, RawSocketClient] = default_impl_type,
        common_headers: Optional[dict] = None,
        **kwargs,
    ):
        self.connection_timeout = connection_timeout
        self.hostname = infra.interfaces.make_address(host, port)
        self.name = f"[{self.hostname}]"
        self.description = description or self.name
        self.is_connected = False
        self.auth = bool(session_auth)
        self.sign = bool(signing_auth)
        self.cose = bool(cose_signing_auth)

        self.client_impl = impl_type(
            self.hostname,
            ca,
            session_auth,
            signing_auth,
            cose_signing_auth,
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
        allow_redirects: bool = True,
        cose_header_parameters_override: Optional[dict] = None,
    ) -> Response:
        if headers is None:
            headers = {}
        r = Request(path, body, http_verb, headers, allow_redirects)
        flush_info([f"{self.description} {r}"], log_capture, 3)
        response = self.client_impl.request(r, timeout, cose_header_parameters_override)
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
        cose_header_parameters_override: Optional[dict] = None,
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
                    path,
                    body,
                    http_verb,
                    headers,
                    timeout,
                    logs,
                    allow_redirects,
                    cose_header_parameters_override,
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
