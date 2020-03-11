# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import socket
import ssl
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
from http.client import HTTPResponse
from io import BytesIO
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


CCF_COMMIT_HEADER = "x-ccf-commit"
CCF_TERM_HEADER = "x-ccf-term"
CCF_GLOBAL_COMMIT_HEADER = "x-ccf-global-commit"
CCF_READ_ONLY_HEADER = "x-ccf-read-only"


class Request:
    def __init__(self, method, params, readonly_hint=None):
        self.method = method
        self.params = params
        self.readonly_hint = readonly_hint


def int_or_none(v):
    return int(v) if v is not None else None


class FakeSocket:
    def __init__(self, bs):
        self.file = BytesIO(bs)

    def makefile(self, *args, **kwargs):
        return self.file


class Response:
    def __init__(self, status, result, error, commit, term, global_commit):
        self.status = status
        self.result = result
        self.error = error
        self.commit = commit
        self.term = term
        self.global_commit = global_commit

    def to_dict(self):
        d = {
            "commit": self.commit,
            "global_commit": self.global_commit,
            "term": self.term,
        }
        if self.result is not None:
            d["result"] = self.result
        else:
            d["error"] = self.error
        return d

    def from_requests_response(rr):
        return Response(
            status=rr.status_code,
            result=rr.json() if rr.ok else None,
            error=None if rr.ok else rr.text,
            commit=int_or_none(rr.headers.get(CCF_COMMIT_HEADER)),
            term=int_or_none(rr.headers.get(CCF_TERM_HEADER)),
            global_commit=int_or_none(rr.headers.get(CCF_GLOBAL_COMMIT_HEADER)),
        )

    def from_raw(raw):
        sock = FakeSocket(raw)
        response = HTTPResponse(sock)
        response.begin()
        raw_body = response.read(raw)
        ok = response.status == 200
        return Response(
            status=response.status,
            result=json.loads(raw_body) if ok else None,
            error=None if ok else raw_body.decode(),
            commit=int_or_none(response.getheader(CCF_COMMIT_HEADER)),
            term=int_or_none(response.getheader(CCF_TERM_HEADER)),
            global_commit=int_or_none(response.getheader(CCF_GLOBAL_COMMIT_HEADER)),
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
            f"{name} {request.method} "
            + truncate(f"{request.params}")
            + (
                f" (RO hint: {request.readonly_hint})"
                if request.readonly_hint is not None
                else ""
            )
            + f"{description}"
        )

    def log_response(self, response):
        LOG.debug(
            truncate(
                "{}".format(
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
            f.write(f">> Request: {request.method}" + os.linesep)
            json.dump(request.params, f, indent=2)
            f.write(os.linesep)

    def log_response(self, response):
        with open(self.path, "a") as f:
            f.write(f"<< Response:" + os.linesep)
            json.dump(response.to_dict() if response else "None", f, indent=2)
            f.write(os.linesep)


class CCFConnectionException(Exception):
    pass


class CurlClient:
    """
    We keep this around in a limited fashion still, because
    the resulting logs nicely illustrate manual usage in a way using the requests API doesn't
    """

    def __init__(
        self,
        host,
        port,
        cert,
        key,
        ca,
        binary_dir,
        connection_timeout,
        request_timeout,
        *args,
        **kwargs,
    ):
        self.host = host
        self.port = port
        self.cert = cert
        self.key = key
        self.ca = ca
        self.binary_dir = binary_dir
        self.connection_timeout = connection_timeout
        self.request_timeout = request_timeout

    def _just_request(self, request, is_signed=False):
        with tempfile.NamedTemporaryFile() as nf:
            msg = json.dumps(request.params).encode()
            LOG.debug(f"Going to call {request.method} with {msg}")
            nf.write(msg)
            nf.flush()
            if is_signed:
                cmd = [os.path.join(self.binary_dir, "scurl.sh")]
            else:
                cmd = ["curl"]

            cmd += [
                f"https://{self.host}:{self.port}/{request.method}",
                "-H",
                "Content-Type: application/json",
                "--data-binary",
                f"@{nf.name}",
                "-i",
                f"-m {self.request_timeout}",
            ]

            if request.readonly_hint:
                cmd.extend(["-H", f"{CCF_READ_ONLY_HEADER}: true"])

            if self.ca:
                cmd.extend(["--cacert", self.ca])
            if self.key:
                cmd.extend(["--key", self.key])
            if self.cert:
                cmd.extend(["--cert", self.cert])
            LOG.debug(f"Running: {' '.join(cmd)}")
            rc = subprocess.run(cmd, capture_output=True)

            if rc.returncode != 0:
                if rc.returncode == 60:  # PEER_FAILED_VERIFICATION
                    raise CCFConnectionException
                if rc.returncode == 28:  # OPERATION_TIMEDOUT
                    raise TimeoutError
                LOG.error(rc.stderr)
                raise RuntimeError(f"Curl failed with return code {rc.returncode}")

            return Response.from_raw(rc.stdout)

    def _request(self, request, is_signed=False):
        end_time = time.time() + self.connection_timeout
        while True:
            try:
                rid = self._just_request(request, is_signed=is_signed)
                # Only the first request gets this timeout logic - future calls
                # call _just_request directly
                self._request = self._just_request
                return rid
            except CCFConnectionException as e:
                # If the handshake fails to due to node certificate not yet
                # being endorsed by the network, sleep briefly and try again
                if time.time() > end_time:
                    raise CCFConnectionException(
                        f"Connection still failing after {self.connection_timeout}s: {e}"
                    )
                LOG.warning(f"Got SSLError exception: {e}")
                time.sleep(0.1)

    def request(self, request):
        return self._request(request, is_signed=False)

    def signed_request(self, request):
        return self._request(request, is_signed=True)


class RequestClient:
    def __init__(
        self,
        host,
        port,
        cert,
        key,
        ca,
        connection_timeout,
        request_timeout,
        *args,
        **kwargs,
    ):
        self.host = host
        self.port = port
        self.cert = cert
        self.key = key
        self.ca = ca
        self.request_timeout = request_timeout
        self.connection_timeout = connection_timeout
        self.session = requests.Session()
        self.session.verify = self.ca
        self.session.cert = (self.cert, self.key)

    def _just_request(self, request, is_signed=False):
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
        if request.readonly_hint:
            extra_headers[CCF_READ_ONLY_HEADER] = "true"

        response = self.session.post(
            f"https://{self.host}:{self.port}/{request.method}",
            json=request.params,
            timeout=self.request_timeout,
            auth=auth_value,
            headers=extra_headers,
        )
        return Response.from_requests_response(response)

    def _request(self, request, is_signed=False):
        end_time = time.time() + self.connection_timeout
        while True:
            try:
                response = self._just_request(request, is_signed=is_signed)
                # Only the first request gets this timeout logic - future calls
                # call _just_request directly
                self._request = self._just_request
                return response
            except requests.exceptions.SSLError as e:
                # If the handshake fails to due to node certificate not yet
                # being endorsed by the network, sleep briefly and try again
                if time.time() > end_time:
                    raise CCFConnectionException(
                        f"Connection still failing after {self.connection_timeout}s: {e}"
                    )
                LOG.warning(f"Got SSLError exception: {e}")
                time.sleep(0.1)
            except requests.exceptions.ReadTimeout as e:
                raise TimeoutError

    def request(self, request):
        return self._request(request, is_signed=False)

    def signed_request(self, request):
        return self._request(request, is_signed=True)


class WSClient:
    def __init__(
        self,
        host,
        port,
        cert,
        key,
        ca,
        connection_timeout,
        request_timeout,
        *args,
        **kwargs,
    ):
        self.host = host
        self.port = port
        self.cert = cert
        self.key = key
        self.ca = ca
        self.request_timeout = request_timeout

    def request(self, request):
        ws = create_connection(
            f"wss://{self.host}:{self.port}",
            sslopt={"certfile": self.cert, "keyfile": self.key, "ca_certs": self.ca},
        )

    def signed_request(self, request):
        raise NotImplementedError("Signed requests not yet implemented over WebSockets")


class CCFClient:
    def __init__(self, *args, **kwargs):
        self.prefix = kwargs.pop("prefix")
        self.description = kwargs.pop("description")
        self.rpc_loggers = (RPCLogger(),)
        self.name = "[{}:{}]".format(kwargs.get("host"), kwargs.get("port"))

        if os.getenv("CURL_CLIENT"):
            self.client_impl = CurlClient(*args, **kwargs)
        elif os.getenv("WEBSOCKETS_CLIENT"):
            self.client_impl = WSClient(*args, **kwargs)
        else:
            self.client_impl = RequestClient(*args, **kwargs)

    def _response(self, response):
        for logger in self.rpc_loggers:
            logger.log_response(response)
        return response

    def request(self, method, params, *args, **kwargs):
        r = Request(f"{self.prefix}/{method}", params, *args, **kwargs)
        description = ""
        if self.description:
            description = f" ({self.description})"
        for logger in self.rpc_loggers:
            logger.log_request(r, self.name, description)

        return self._response(self.client_impl.request(r))

    def signed_request(self, method, params, *args, **kwargs):
        r = Request(f"{self.prefix}/{method}", params, *args, **kwargs)

        description = ""
        if self.description:
            description = f" ({self.description}) [signed]"
        for logger in self.rpc_loggers:
            logger.log_request(r, self.name, description)

        return self._response(self.client_impl.signed_request(r))

    def do(self, *args, **kwargs):
        expected_result = None
        expected_error_code = None
        if "expected_result" in kwargs:
            expected_result = kwargs.pop("expected_result")
        if "expected_error_code" in kwargs:
            expected_error_code = kwargs.pop("expected_error_code")

        r = self.rpc(*args, **kwargs)

        if expected_result is not None:
            assert expected_result == r.result

        if expected_error_code is not None:
            assert expected_error_code == r.error["code"]
        return r

    def rpc(self, *args, **kwargs):
        if "signed" in kwargs and kwargs.pop("signed"):
            return self.signed_request(*args, **kwargs)
        else:
            return self.request(*args, **kwargs)


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
    )

    if log_file is not None:
        c.rpc_loggers += (RPCFileLogger(log_file),)

    yield c
