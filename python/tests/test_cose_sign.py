# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import base64
import datetime
from typing import Tuple
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
import ccf.cose
import cbor2


def make_private_key(curve: ec.EllipticCurve):
    return ec.generate_private_key(curve=curve, backend=default_backend())


def make_pem_pair(priv) -> Tuple[str, str]:
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode("ascii")
    pub_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(
        "ascii"
    )
    return priv_pem, pub_pem


def make_self_signed_cert(priv, subject_name: str):
    subject = issuer = x509.Name(
        [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, subject_name)]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now())
        .not_valid_after(datetime.datetime.now() + datetime.timedelta(days=365))
        .sign(priv, hashes.SHA256(), default_backend())
    )
    return cert.public_bytes(Encoding.PEM).decode("ascii")


def test_create_cose_sign1_finish():
    """
    Check create_cose_sign1_finish() produces the same output when passed
    a signature as create_cose_sign1().
    """
    priv = make_private_key(ec.SECP256R1())
    priv_pem, pub_pem = make_pem_pair(priv)
    cert = make_self_signed_cert(priv, "example.com")

    payload = b"Hello World"

    cose_sign1 = ccf.cose.create_cose_sign1(payload, priv_pem, cert)

    _, _, _, sig = cbor2.loads(cose_sign1).value
    b64_sig = base64.urlsafe_b64encode(sig)

    ccf.cose.validate_cose_sign1(priv.public_key(), cose_sign1)
    finished_cose_sign1 = ccf.cose.create_cose_sign1_finish(payload, cert, b64_sig)
    assert cose_sign1 == finished_cose_sign1
