# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from ccf.cose import from_cryptography_eckey_obj

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from pycose.messages import Sign1Message  # type: ignore


def get_cert_key_type(cert_pem: str) -> str:
    cert = load_pem_x509_certificate(cert_pem.encode("ascii"), default_backend())
    if isinstance(cert.public_key(), EllipticCurvePublicKey):
        return "ec"
    raise NotImplementedError("unsupported key type")


def verify_cose_sign1(buf: bytes, cert_pem: str):
    key_type = get_cert_key_type(cert_pem)
    cert = load_pem_x509_certificate(cert_pem.encode("ascii"), default_backend())
    key = cert.public_key()
    if key_type == "ec":
        cose_key = from_cryptography_eckey_obj(key)
    else:
        raise NotImplementedError("unsupported key type")
    msg = Sign1Message.decode(buf)
    msg.key = cose_key
    if not msg.verify_signature():
        raise ValueError("signature is invalid")
    return msg
