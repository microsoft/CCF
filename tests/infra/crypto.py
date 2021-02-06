# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from typing import Tuple, Optional
import base64
from enum import IntEnum
import secrets
import datetime

import coincurve
from coincurve._libsecp256k1 import ffi, lib  # pylint: disable=no-name-in-module
from coincurve.context import GLOBAL_CONTEXT

from cryptography.exceptions import InvalidSignature
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


# This function calls the native API and does not rely on the
# imported library's implementation. Though not being used by
# the current test, it might still be helpful to have this
# sequence of native calls for verification, in case the
# imported library's code changes.
def verify_recover_secp256k1_bc_native(
    signature, req, hasher=coincurve.utils.sha256, context=GLOBAL_CONTEXT
):
    # Compact
    native_rec_sig = ffi.new("secp256k1_ecdsa_recoverable_signature *")
    raw_sig, recovery_id = signature[:64], coincurve.utils.bytes_to_int(signature[64:])
    lib.secp256k1_ecdsa_recoverable_signature_parse_compact(
        context.ctx, native_rec_sig, raw_sig, recovery_id
    )

    # Recover public key
    native_public_key = ffi.new("secp256k1_pubkey *")
    msg_hash = hasher(req) if hasher is not None else req
    lib.secp256k1_ecdsa_recover(
        context.ctx, native_public_key, native_rec_sig, msg_hash
    )

    # Convert
    native_standard_sig = ffi.new("secp256k1_ecdsa_signature *")
    lib.secp256k1_ecdsa_recoverable_signature_convert(
        context.ctx, native_standard_sig, native_rec_sig
    )

    # Verify
    ret = lib.secp256k1_ecdsa_verify(
        context.ctx, native_standard_sig, msg_hash, native_public_key
    )
    return ret


def verify_recover_secp256k1_bc(
    signature, req, hasher=coincurve.utils.sha256, context=GLOBAL_CONTEXT
):
    msg_hash = hasher(req) if hasher is not None else req
    rec_sig = coincurve.ecdsa.deserialize_recoverable(signature)
    public_key = coincurve.PublicKey(coincurve.ecdsa.recover(req, rec_sig))
    n_sig = coincurve.ecdsa.recoverable_convert(rec_sig)

    if not lib.secp256k1_ecdsa_verify(
        context.ctx, n_sig, msg_hash, public_key.public_key
    ):
        raise RuntimeError("Failed to verify SECP256K1 bitcoin signature")


def verify_request_sig(raw_cert, sig, req, request_body, md):
    try:
        cert = x509.load_der_x509_certificate(raw_cert, backend=default_backend())

        # Verify that the request digest matches the hash of the body
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(request_body)
        raw_req_digest = h.finalize()
        header_digest = base64.b64decode(req.decode().split("SHA-256=")[1])
        assert (
            header_digest == raw_req_digest
        ), "Digest header does not match request body"

        pub_key = cert.public_key()
        signature_hash_alg = ec.ECDSA(
            hashes.SHA256()
            if md == CCFDigestType.MD_SHA256
            else cert.signature_hash_algorithm
        )
        pub_key.verify(sig, req, signature_hash_alg)
    except InvalidSignature as e:
        # we support a non-standard curve, which is also being
        # used for bitcoin.
        if pub_key._curve.name != "secp256k1":  # pylint: disable=protected-access
            raise e

        verify_recover_secp256k1_bc(sig, req)


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
