# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import grpc
import time

# pylint: disable=import-error
import executor_registration_pb2 as ExecutorRegistration

# pylint: disable=import-error
import executor_registration_pb2_grpc as RegistrationService

# TODO: Generate these in tests/external_executor
# pylint: disable=import-error
import attestation_container_pb2_grpc as AttestationContainerService

# pylint: disable=import-error
import attestation_container_pb2 as AttestationContainer

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

from loguru import logger as LOG

DEFAULT_VALIDITY_PERIOD_DAYS = 90


def generate_ec_keypair(curve=ec.SECP256R1):
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


def generate_self_signed_cert(
    priv_key_pem, validity_period_days=DEFAULT_VALIDITY_PERIOD_DAYS
):
    cn = "External executor"
    valid_from = datetime.datetime.utcnow()
    validity_days = validity_period_days
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


def register_new_executor(
    node_public_rpc_address,
    service_certificate_bytes,
    supported_endpoints=None,
    timeout=3,
):
    # Generate a new executor identity
    key_priv_pem, _ = generate_ec_keypair()
    cert = generate_self_signed_cert(key_priv_pem)

    # Channel with attestation container
    end_time = time.time() + timeout
    while True:
        with grpc.insecure_channel(
            target="unix:///tmp/attestation-container.sock",
        ) as channel:
            message = AttestationContainer.FetchAttestationRequest()
            message.report_data = b"lala"
            stub = AttestationContainerService.AttestationContainerStub(channel)

            # As containers in the same container group may startup at different speeds,
            # wait a reasonable timeout until attestation container is up.

            LOG.info("Trying")
            try:
                reply = stub.FetchAttestation(message)
            except grpc.RpcError:
                if time.time() > end_time:
                    raise TimeoutError(
                        f"Attestation container could not be reached after {timeout}s. Stopping."
                    )
                LOG.trace("Attestation container starting up, retrying...")
                time.sleep(0.1)
                continue
            else:
                break

            LOG.error(f"Reply: {reply}")

        # TODO:
        # 1. Generate attestation container source from proto files
        # 2. Import here
        # 3. Issue request with report data

    # Create a default NewExecutor message
    message = ExecutorRegistration.NewExecutor()
    message.attestation.format = ExecutorRegistration.Attestation.AMD_SEV_SNP_V1
    message.attestation.quote = b"testquote"
    message.attestation.endorsements = b"testendorsement"

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
