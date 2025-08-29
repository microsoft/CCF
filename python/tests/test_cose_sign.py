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
from cryptography.hazmat.primitives.asymmetric import utils
import ccf.cose
import cbor2
import pytest


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


def i2osp(x: int, x_len: int) -> bytes:
    """
    cwt.algs.ec2.i2osp
    """
    if x >= 256**x_len:
        raise ValueError("integer too large")
    digits = []
    while x:
        digits.append(int(x % 256))
        x //= 256
    for _ in range(x_len - len(digits)):
        digits.append(0)
    return bytes.fromhex("".join("%.2x" % x for x in digits[::-1]))


def hash_algo(priv: ec.EllipticCurvePrivateKey):
    return {
        256: hashes.SHA256(),
        384: hashes.SHA384(),
        521: hashes.SHA512(),
    }[priv.key_size]


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
        .sign(priv, hash_algo(priv), default_backend())
    )
    return cert.public_bytes(Encoding.PEM).decode("ascii")


@pytest.mark.parametrize("curve", [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()])
def test_create_cose_sign1_finish(curve):
    """
    Check create_cose_sign1_finish() produces the same output when passed
    a signature as create_cose_sign1().
    """
    priv = make_private_key(curve)
    priv_pem, pub_pem = make_pem_pair(priv)
    cert = make_self_signed_cert(priv, "example.com")

    payload = b"Hello World"

    cose_sign1 = ccf.cose.create_cose_sign1(payload, priv_pem, cert)

    _, _, _, sig = cbor2.loads(cose_sign1).value
    b64_sig = base64.urlsafe_b64encode(sig)

    ccf.cose.validate_cose_sign1(priv.public_key(), cose_sign1)
    finished_cose_sign1 = ccf.cose.create_cose_sign1_finish(payload, cert, b64_sig)
    assert cose_sign1 == finished_cose_sign1


@pytest.mark.parametrize("curve", [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()])
def test_create_cose_sign1_prepare_and_finish(curve):
    """
    Check adding performing a signature externally on the output of
    cose.create_cose_sign1_prepare() and packaging it with
    cose.create_cose_sign1_finish() produces a valid COSE_Sign1.
    """
    priv = make_private_key(curve)
    cert = make_self_signed_cert(priv, "example.com")
    payload = b"Hello"

    tbs = ccf.cose.create_cose_sign1_prepare(payload, cert)

    alg = tbs["alg"]
    raw_value = base64.b64decode(tbs["value"])

    assert alg == ccf.cose.default_algorithm_for_key(priv.public_key())
    signature = priv.sign(raw_value, ec.ECDSA(utils.Prehashed(hash_algo(priv))))
    r, s = utils.decode_dss_signature(signature)
    num_bytes = (priv.key_size + 7) // 8
    raw_signature = i2osp(r, num_bytes) + i2osp(s, num_bytes)

    b64_sig = base64.urlsafe_b64encode(raw_signature)
    finished_cose_sign1 = ccf.cose.create_cose_sign1_finish(payload, cert, b64_sig)
    ccf.cose.validate_cose_sign1(priv.public_key(), finished_cose_sign1)
