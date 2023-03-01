# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import requests
import grpc
import os
from base64 import b64decode

from loguru import logger as LOG

# pylint: disable=import-error
import kv_pb2 as KV

# pylint: disable=import-error
import http_pb2 as HTTP

# pylint: disable=import-error
import kv_pb2_grpc as Service

# pylint: disable=no-name-in-module
from google.protobuf.empty_pb2 import Empty as Empty

# pylint: disable=import-error
import executor_registration_pb2 as ExecutorRegistration

# pylint: disable=import-error
import executor_registration_pb2_grpc as RegistrationService

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives import hashes
import datetime


def generate_self_signed_cert(priv_key_pem: str) -> str:
    cn = "External executor"
    valid_from = datetime.datetime.utcnow()
    validity_days = 90
    priv = load_pem_private_key(priv_key_pem.encode("ascii"), None, default_backend())
    pub = priv.public_key()
    issuer_priv = load_pem_private_key(
        priv_key_pem.encode("ascii"), None, default_backend()
    )
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_from + datetime.timedelta(days=validity_days))
    )

    cert = builder.sign(issuer_priv, hashes.SHA256(), default_backend())

    return cert.public_bytes(Encoding.PEM).decode("ascii")


class WikiCacherExecutor:
    API_VERSION = "v1"
    PROJECT = "wikipedia"
    LANGUAGE = "en"

    CACHE_TABLE = "wiki_descriptions"
    supported_endpoints = None

    def __init__(
        self,
        node_public_rpc_address,
        credentials,
        base_url="https://api.wikimedia.org",
        label=None,
    ):
        self.node_public_rpc_address = node_public_rpc_address
        self.base_url = base_url
        if label is not None:
            self.prefix = f"[{label}] "
        else:
            self.prefix = ""
        self.credentials = credentials

        self.handled_requests_count = 0

    @staticmethod
    def get_supported_endpoints(topics):
        endpoints = []
        for topic in topics:
            endpoints.append(("POST", "/update_cache/" + topic))
            endpoints.append(("GET", "/article_description/" + topic))
        return endpoints

    def _api_base(self):
        return "/".join(
            (
                self.base_url,
                "core",
                self.API_VERSION,
                self.PROJECT,
                self.LANGUAGE,
            )
        )

    def _get_description(self, title):
        url = "/".join((self._api_base(), "page", title, "description"))
        LOG.debug(f"{self.prefix}Requesting {url}")
        r = requests.get(url, timeout=3)
        if r.status_code == 200:
            return r.json()["description"]
        LOG.error(f"{self.prefix}{r}")

    def _execute_update_cache(self, kv_stub, request, response):
        prefix = "/update_cache/"
        title = request.uri[len(prefix) :]
        description = self._get_description(title)
        if description == None:
            response.status_code = HTTP.HttpStatusCode.BAD_GATEWAY
            response.body = f"Error when fetching article with title '{title}'".encode(
                "utf-8"
            )
        else:
            kv_stub.Put(
                KV.KVKeyValue(
                    table=self.CACHE_TABLE,
                    key=title.encode("utf-8"),
                    value=description.encode("utf-8"),
                )
            )
            response.status_code = HTTP.HttpStatusCode.OK
            response.body = f"Successfully updated cache with description of '{title}':\n\n{description}".encode(
                "utf-8"
            )

    def _execute_get_description(self, kv_stub, request, response):
        prefix = "/article_description/"
        title = request.uri[len(prefix) :]
        result = kv_stub.Get(
            KV.KVKey(table=self.CACHE_TABLE, key=title.encode("utf-8"))
        )

        if not result.HasField("optional"):
            response.status_code = HTTP.HttpStatusCode.NOT_FOUND
            response.body = f"No description for '{title}' in cache".encode("utf-8")
        else:
            response.status_code = HTTP.HttpStatusCode.OK
            response.body = result.optional.value

    def run_loop(self, activated_event=None):
        LOG.info(f"{self.prefix}Beginning executor loop")

        with grpc.secure_channel(
            target=self.node_public_rpc_address,
            credentials=self.credentials,
        ) as channel:
            stub = Service.KVStub(channel)

            for work in stub.Activate(Empty()):
                if work.HasField("activated"):
                    if activated_event is not None:
                        activated_event.set()
                    continue

                if work.HasField("work_done"):
                    break

                assert work.HasField("request_description")
                request = work.request_description
                self.handled_requests_count += 1

                response = KV.ResponseDescription(
                    status_code=HTTP.HttpStatusCode.NOT_FOUND
                )

                if request.method == "POST" and request.uri.startswith(
                    "/update_cache/"
                ):
                    LOG.info(f"{self.prefix}Updating article in cache: {request.uri}")
                    self._execute_update_cache(stub, request, response)

                elif request.method == "GET" and request.uri.startswith(
                    "/article_description/"
                ):
                    LOG.info(
                        f"{self.prefix}Retrieving description from cache: {request.uri}"
                    )
                    self._execute_get_description(stub, request, response)

                else:
                    LOG.error(
                        f"{self.prefix}Unhandled request: {request.method} {request.uri}"
                    )
                    response.status_code = HTTP.HttpStatusCode.NOT_FOUND
                    response.body = (
                        f"No resource found at {request.method} {request.uri}".encode(
                            "utf-8"
                        )
                    )

                stub.EndTx(response)

        LOG.info(f"{self.prefix}Ended executor loop")

    def terminate(self):
        with grpc.secure_channel(
            target=self.node_public_rpc_address,
            credentials=self.credentials,
        ) as channel:
            stub = Service.KVStub(channel)
            stub.Deactivate(Empty())


def generate_ec_keypair(curve: ec.EllipticCurve = ec.SECP256R1):
    priv = ec.generate_private_key(
        curve=curve,
        backend=default_backend(),
    )
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode("ascii")
    pub_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(
        "ascii"
    )
    return priv_pem, pub_pem


def register_new_executor(
    node_public_rpc_address,
    service_certificate_bytes,
    supported_endpoints=None,
    message=None,
):
    # Generate a new executor identity
    key_priv_pem, _ = generate_ec_keypair()
    cert = generate_self_signed_cert(key_priv_pem)

    if message is None:
        # Create a default NewExecutor message
        message = ExecutorRegistration.NewExecutor()
        message.attestation.format = ExecutorRegistration.Attestation.AMD_SEV_SNP_V1
        message.attestation.quote = b"testquote"
        message.attestation.endorsements = b"testendorsement"
        message.supported_endpoints.add(method="GET", uri="/app/foo/bar")

        if supported_endpoints:
            for method, uri in supported_endpoints:
                message.supported_endpoints.add(method=method, uri=uri)

    message.cert = cert.encode()

    # Connect anonymously to register this executor
    anonymous_credentials = grpc.ssl_channel_credentials(service_certificate_bytes)

    with grpc.secure_channel(
        target=node_public_rpc_address,
        credentials=anonymous_credentials,
    ) as channel:
        stub = RegistrationService.ExecutorRegistrationStub(channel)
        r = stub.RegisterExecutor(message)
        assert r.details == "Executor registration is accepted."
        LOG.success(f"Registered new executor {r.executor_id}")

    # Create (and return) credentials that allow authentication as this new executor
    executor_credentials = grpc.ssl_channel_credentials(
        service_certificate_bytes,
        private_key=key_priv_pem.encode(),
        certificate_chain=cert.encode(),
    )

    return executor_credentials


if __name__ == "__main__":
    ccf_address = os.environ.get("CCF_CORE_NODE_RPC_ADDRESS")
    service_certificate_bytes = b64decode(
        os.environ.get("CCF_CORE_SERVICE_CERTIFICATE")
    )
    credentials = register_new_executor(
        ccf_address,
        service_certificate_bytes,
        WikiCacherExecutor.get_supported_endpoints({"Earth"}),
    )
    e = WikiCacherExecutor(ccf_address, credentials)
    e.run_loop()
