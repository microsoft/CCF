# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from typing import Optional

import cbor2
import cose.headers
from cose.keys.ec2 import EC2Key
from cose.keys.curves import P256, P384, P521
from cose.keys.keyparam import EC2KpCurve, EC2KpX, EC2KpY, EC2KpD
from cose.messages import Sign1Message
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

Pem = str


def from_cryptography_eckey_obj(ext_key) -> EC2Key:
    """
    Returns an initialized COSE Key object of type EC2Key.
    :param ext_key: Python cryptography key.
    :return: an initialized EC key
    """
    if hasattr(ext_key, "private_numbers"):
        priv_nums = ext_key.private_numbers()
        pub_nums = priv_nums.public_numbers
    else:
        priv_nums = None
        pub_nums = ext_key.public_numbers()

    if pub_nums.curve.name == "secp256r1":
        curve = P256
    elif pub_nums.curve.name == "secp384r1":
        curve = P384
    elif pub_nums.curve.name == "secp521r1":
        curve = P521
    else:
        raise NotImplementedError("unsupported curve")

    cose_key = {}
    if pub_nums:
        cose_key.update(
            {
                EC2KpCurve: curve,
                EC2KpX: pub_nums.x.to_bytes(curve.size, "big"),
                EC2KpY: pub_nums.y.to_bytes(curve.size, "big"),
            }
        )
    if priv_nums:
        cose_key.update(
            {
                EC2KpD: priv_nums.private_value.to_bytes(curve.size, "big"),
            }
        )
    return EC2Key.from_dict(cose_key)


def default_algorithm_for_key(key) -> str:
    """
    Get the default algorithm for a given key, based on its
    type and parameters.
    """
    if isinstance(key, EllipticCurvePublicKey):
        if isinstance(key.curve, ec.SECP256R1):
            return "ES256"
        elif isinstance(key.curve, ec.SECP384R1):
            return "ES384"
        elif isinstance(key.curve, ec.SECP521R1):
            return "ES512"
        else:
            raise NotImplementedError("unsupported curve")
    else:
        raise NotImplementedError("unsupported key type")


def get_priv_key_type(priv_pem: str) -> str:
    key = load_pem_private_key(priv_pem.encode("ascii"), None, default_backend())
    if isinstance(key, EllipticCurvePrivateKey):
        return "ec"
    raise NotImplementedError("unsupported key type")


def cert_fingerprint(cert_pem: Pem):
    cert = load_pem_x509_certificate(cert_pem.encode("ascii"), default_backend())
    return cert.fingerprint(hashes.SHA256()).hex().encode("utf-8")


def create_cose_sign1(
    payload: bytes,
    key_priv_pem: Pem,
    cert_pem: Pem,
    additional_headers: Optional[dict] = None,
) -> bytes:
    key_type = get_priv_key_type(key_priv_pem)

    cert = load_pem_x509_certificate(cert_pem.encode("ascii"), default_backend())
    alg = default_algorithm_for_key(cert.public_key())
    kid = cert_fingerprint(cert_pem)

    headers = {cose.headers.Algorithm: alg, cose.headers.KID: kid}
    headers.update(additional_headers or {})
    msg = Sign1Message(phdr=headers, payload=payload)

    key = load_pem_private_key(key_priv_pem.encode("ascii"), None, default_backend())
    if key_type == "ec":
        cose_key = from_cryptography_eckey_obj(key)
    else:
        raise NotImplementedError("unsupported key type")
    msg.key = cose_key

    return msg.encode()


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


def detach_content(msg: bytes):
    m = cbor2.loads(msg)
    content = m.value[2]
    m.value[2] = None
    return content, cbor2.dumps(m)


def attach_content(content, detached_envelope):
    m = cbor2.loads(detached_envelope)
    m.value[2] = content
    return cbor2.dumps(m)


PRIV = """-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDMwIszb3ZmKpeHq/vPoz6qnxheI89T2IZpKFQHJwQrvuaFFLDUKK9Z
jKRMshAeALagBwYFK4EEACKhZANiAAQ38JreTF2uKVaTKBd7fAkIy2bg5U6T0O+H
wcxJOLgqK+fwidnVlPG+GQUwIj6ik7Xp/0Ig7RVSAyAjcpYWL4dHU5gJ/g9PruHz
cnmFtP88dARPH2EKy0n/iGh9yXD3bXw=
-----END EC PRIVATE KEY-----
"""

PUB = """-----BEGIN CERTIFICATE-----
MIIBtjCCATygAwIBAgIUJCUauYlNsJ76zOUomey4cF7F+pUwCgYIKoZIzj0EAwMw
EjEQMA4GA1UEAwwHbWVtYmVyMDAeFw0yMjA5MDYxMzQ2NDlaFw0yMzA5MDYxMzQ2
NDlaMBIxEDAOBgNVBAMMB21lbWJlcjAwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQ3
8JreTF2uKVaTKBd7fAkIy2bg5U6T0O+HwcxJOLgqK+fwidnVlPG+GQUwIj6ik7Xp
/0Ig7RVSAyAjcpYWL4dHU5gJ/g9PruHzcnmFtP88dARPH2EKy0n/iGh9yXD3bXyj
UzBRMB0GA1UdDgQWBBTpme2NGI1y3OY8XYT5XwcuuvG55jAfBgNVHSMEGDAWgBTp
me2NGI1y3OY8XYT5XwcuuvG55jAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMD
A2gAMGUCMDg1QddcE5YFrcHmFvyXW2s7LaV0NYx24lwImrgWXQTOv7iNXAfrogzP
CQxyHqkSxgIxANmkmLCojf5NCvwxI5tf37i6zGQ0c9zR0P9b4FtcznEtrbzmXfdJ
b2H04E57XZmVdg==
-----END CERTIFICATE-----
"""

if __name__ == "__main__":
    signed_statement = create_cose_sign1(
        b"governance js here", PRIV, PUB, {"ccf_governance_action": "proposal"}
    )
    msg = verify_cose_sign1(signed_statement, PUB)
    assert msg.phdr[cose.headers.KID] == cert_fingerprint(PUB), (
        msg.phdr[cose.headers.KID],
        cert_fingerprint(PUB),
    )
    content, detached_envelope = detach_content(signed_statement)
    signed_statement = attach_content(content, detached_envelope)
    msg = verify_cose_sign1(signed_statement, PUB)
    signed_statement = create_cose_sign1(
        b"governance js here",
        PRIV,
        PUB,
        {"ccf_governance_action": "proposal", "ccf_governance_proposal_id": "12345"},
    )
