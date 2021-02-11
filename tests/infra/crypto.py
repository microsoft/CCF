# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from typing import Tuple, Optional
import base64
from enum import IntEnum
import secrets
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import (
    load_pem_x509_certificate,
    load_der_x509_certificate,
)
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import jwt

RECOMMENDED_RSA_PUBLIC_EXPONENT = 65537


# As per tls::MDType
class CCFDigestType(IntEnum):
    MD_NONE = 0
    MD_SHA1 = 1
    MD_SHA256 = 2
    MD_SHA384 = 3
    MD_SHA512 = 4


def verify_request_sig(raw_cert, sig, req, request_body, md):
    cert = x509.load_der_x509_certificate(raw_cert, backend=default_backend())

    # Verify that the request digest matches the hash of the body
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h.update(request_body)
    raw_req_digest = h.finalize()
    header_digest = base64.b64decode(req.decode().split("SHA-256=")[1])
    assert header_digest == raw_req_digest, "Digest header does not match request body"

    pub_key = cert.public_key()
    signature_hash_alg = ec.ECDSA(
        hashes.SHA256()
        if md == CCFDigestType.MD_SHA256
        else cert.signature_hash_algorithm
    )
    pub_key.verify(sig, req, signature_hash_alg)


def generate_aes_key(key_bits: int) -> bytes:
    return secrets.token_bytes(key_bits // 8)


def generate_rsa_keypair(key_size: int) -> Tuple[str, str]:
    priv = rsa.generate_private_key(
        public_exponent=RECOMMENDED_RSA_PUBLIC_EXPONENT,
        key_size=key_size,
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


def generate_cert(priv_key_pem: str, cn="dummy") -> str:
    priv = load_pem_private_key(priv_key_pem.encode("ascii"), None, default_backend())
    pub = priv.public_key()
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))
        .sign(priv, hashes.SHA256(), default_backend())
    )

    return cert.public_bytes(Encoding.PEM).decode("ascii")


def unwrap_key_rsa_oaep(
    wrapped_key: bytes, wrapping_key_priv_pem: str, label: Optional[bytes] = None
) -> bytes:
    wrapping_key = load_pem_private_key(
        wrapping_key_priv_pem.encode("ascii"), None, default_backend()
    )
    unwrapped = wrapping_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=label,
        ),
    )
    return unwrapped


def pub_key_pem_to_der(pem: str) -> bytes:
    cert = load_pem_public_key(pem.encode("ascii"), default_backend())
    return cert.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def create_jwt(body_claims: dict, key_priv_pem: str, key_id: str) -> str:
    return jwt.encode(
        body_claims, key_priv_pem, algorithm="RS256", headers={"kid": key_id}
    )


def cert_pem_to_der(pem: str) -> bytes:
    cert = load_pem_x509_certificate(pem.encode("ascii"), default_backend())
    return cert.public_bytes(Encoding.DER)


def cert_der_to_pem(der: bytes) -> str:
    cert = load_der_x509_certificate(der, default_backend())
    return cert.public_bytes(Encoding.PEM).decode("ascii")


def are_certs_equal(pem1: str, pem2: str) -> bool:
    cert1 = load_pem_x509_certificate(pem1.encode(), default_backend())
    cert2 = load_pem_x509_certificate(pem2.encode(), default_backend())
    return cert1 == cert2
