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
    def __init__(self, method, params, readonly_hint=None):
        self.method = method
        self.params = params
        self.readonly_hint = readonly_hint


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


class RPCLogger:
    def log_request(self, request, name, description):
        LOG.info(
            truncate(
                f"{name} {request.method} {request.params}"
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
            f.write(f">> Request: {request.method}" + os.linesep)
            json.dump(request.params, f, indent=2)
            f.write(os.linesep)

    def log_response(self, id, response):
        with open(self.path, "a") as f:
            f.write(f"<< Response {id} :" + os.linesep)
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
                "-w \\n%{http_code}",
                f"-m {self.request_timeout}",
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
                if rc.returncode == 60:  # PEER_FAILED_VERIFICATION
                    raise CCFConnectionException
                if rc.returncode == 28:  # OPERATION_TIMEDOUT
                    raise TimeoutError
                LOG.error(rc.stderr)
                raise RuntimeError(f"Curl failed with return code {rc.returncode}")

            # The response status code is displayed on the last line of
            # the output (via -w option)
            rep, status_code = rc.stdout.decode().rsplit("\n", 1)
            if int(status_code) != 200:
                LOG.error(rep)
                raise RuntimeError(f"Curl failed with status code {status_code}")

            return rep.encode()

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
                LOG.error(f"Got SSLError exception: {e}")
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

        rep = self.session.post(
            f"https://{self.host}:{self.port}/{request.method}",
            json=request.params,
            timeout=self.request_timeout,
            auth=auth_value,
        )
        return rep.content

    def _request(self, request, is_signed=False):
        end_time = time.time() + self.connection_timeout
        while True:
            try:
                rid = self._just_request(request, is_signed=is_signed)
                # Only the first request gets this timeout logic - future calls
                # call _just_request directly
                self._request = self._just_request
                return rid
            except requests.exceptions.SSLError as e:
                # If the handshake fails to due to node certificate not yet
                # being endorsed by the network, sleep briefly and try again
                if time.time() > end_time:
                    raise CCFConnectionException(
                        f"Connection still failing after {self.connection_timeout}s: {e}"
                    )
                LOG.error(f"Got SSLError exception: {e}")
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

    def _response(self, msg):
        r = Response(0)
        r.from_json(msg)
        for logger in self.rpc_loggers:
            logger.log_response(r.id, r)
        return r

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

        r = self.request(*args, **kwargs)

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
