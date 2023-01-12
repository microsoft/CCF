# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from typing import Tuple, Optional
import base64
from enum import IntEnum
import secrets
import datetime
import hashlib
from pyasn1.type.useful import UTCTime


from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import (
    load_pem_x509_certificate,
    load_der_x509_certificate,
)
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives import hashes, keywrap
from cryptography.hazmat.backends import default_backend

import jwt

RECOMMENDED_RSA_PUBLIC_EXPONENT = 65537


# As per tls::MDType
class CCFDigestType(IntEnum):
    NONE = 0
    SHA1 = 1
    SHA256 = 2
    SHA384 = 3
    SHA512 = 4


def verify_request_sig(raw_cert, sig, req, request_body, md):
    cert = x509.load_pem_x509_certificate(raw_cert, backend=default_backend())

    # Verify that the request digest matches the hash of the body
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h.update(request_body)
    raw_req_digest = h.finalize()
    header_digest = base64.b64decode(req.decode().split("SHA-256=")[1])
    assert header_digest == raw_req_digest, "Digest header does not match request body"

    pub_key = cert.public_key()
    signature_hash_alg = ec.ECDSA(
        hashes.SHA256()
        if CCFDigestType[md] == CCFDigestType.SHA256
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


def generate_ec_keypair(curve: ec.EllipticCurve = ec.SECP256R1) -> Tuple[str, str]:
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


def generate_eddsa_keypair() -> Tuple[str, str]:
    # Currently only Curve25519 is supported
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode("ascii")
    pub_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(
        "ascii"
    )
    return priv_pem, pub_pem


def generate_cert(
    priv_key_pem: str,
    cn=None,
    issuer_priv_key_pem=None,
    issuer_cn=None,
    ca=False,
    valid_from=None,
    validity_days=10,
) -> str:
    cn = cn or "dummy"
    if issuer_priv_key_pem is None:
        issuer_priv_key_pem = priv_key_pem
    if issuer_cn is None:
        issuer_cn = cn
    if valid_from is None:
        valid_from = datetime.datetime.utcnow()
    priv = load_pem_private_key(priv_key_pem.encode("ascii"), None, default_backend())
    pub = priv.public_key()
    issuer_priv = load_pem_private_key(
        issuer_priv_key_pem.encode("ascii"), None, default_backend()
    )
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
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
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )

    cert = builder.sign(issuer_priv, hashes.SHA256(), default_backend())

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


def unwrap_key_aes_pad(wrapped_key: bytes, wrapping_key: bytes) -> bytes:
    return keywrap.aes_key_unwrap_with_padding(wrapping_key, wrapped_key)


def unwrap_key_rsa_oaep_aes_pad(
    data: bytes, oaep_key_priv_pem: str, label: Optional[bytes] = None
) -> bytes:
    oaep_key = load_pem_private_key(
        oaep_key_priv_pem.encode("ascii"), None, default_backend()
    )
    w_aes_sz = oaep_key.key_size // 8
    w_aes_key = data[:w_aes_sz]
    w_target_key = data[w_aes_sz:]
    t_aes_key = unwrap_key_rsa_oaep(w_aes_key, oaep_key_priv_pem, label)
    return unwrap_key_aes_pad(w_target_key, t_aes_key)


def sign(algorithm: dict, key_pem: str, data: bytes) -> bytes:
    key = load_pem_private_key(key_pem.encode("ascii"), None, default_backend())
    if "hash" not in algorithm:
        pass
    elif algorithm["hash"] == "SHA-256":
        hash_alg = hashes.SHA256()
    else:
        raise ValueError("Unsupported hash algorithm")
    if isinstance(key, rsa.RSAPrivateKey):
        if algorithm["name"] == "RSASSA-PKCS1-v1_5":
            return key.sign(data, padding.PKCS1v15(), hash_alg)
        else:
            raise ValueError("Unsupported signing algorithm")
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        if algorithm["name"] == "ECDSA":
            # pylint: disable=no-value-for-parameter
            signature = key.sign(data, ec.ECDSA(hash_alg))
            encoding = algorithm.get("encoding", "ieee-p1363")
            if encoding == "der":
                pass
            elif encoding == "ieee-p1363":
                key_size_bits = key.key_size
                signature = convert_ecdsa_signature_from_der_to_p1363(
                    signature, key_size_bits
                )
            else:
                raise ValueError(f"Unknown encoding: {encoding}")
            return signature
        else:
            raise ValueError("Unsupported signing algorithm")
    elif isinstance(key, ed25519.Ed25519PrivateKey):
        return key.sign(data)
    else:
        raise ValueError("Unsupported key type")


def convert_ecdsa_signature_from_der_to_p1363(
    signature_der: bytes, key_size_bits: int
) -> bytes:
    (r, s) = decode_dss_signature(signature_der)
    assert key_size_bits % 8 == 0
    n = key_size_bits // 8
    signature_p1363 = r.to_bytes(n, byteorder="big") + s.to_bytes(n, byteorder="big")
    return signature_p1363


def verify_signature(
    signature: bytes, data: bytes, key_pub_pem: str, hash_alg: Optional[str] = None
):
    key_pub = load_pem_public_key(key_pub_pem.encode())
    if isinstance(key_pub, rsa.RSAPublicKey):
        if hash_alg != "SHA-256":
            raise ValueError("Unsupported hash algorithm")
        key_pub.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(key_pub, ec.EllipticCurvePublicKey):
        if hash_alg != "SHA-256":
            raise ValueError("Unsupported hash algorithm")
        key_pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    elif isinstance(key_pub, ed25519.Ed25519PublicKey):
        return key_pub.verify(signature, data)
    else:
        raise ValueError("Unsupported key type")


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


def compute_public_key_der_hash_hex_from_pem(pem: str):
    cert = load_pem_x509_certificate(pem.encode(), default_backend())
    pub_key = cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(pub_key).hexdigest()


def compute_cert_der_hash_hex_from_pem(pem: str):
    cert = load_pem_x509_certificate(pem.encode(), default_backend())
    return cert.fingerprint(hashes.SHA256()).hex()


def get_san_from_pem_cert(pem: str):
    cert = load_pem_x509_certificate(pem.encode(), default_backend())
    return cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value


def check_key_pair_pem(private: str, public: str, password=None) -> bool:
    prv = load_pem_private_key(private.encode(), password=password)
    pub = load_pem_public_key(public.encode())
    prv_pub_der = prv.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    pub_der = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return prv_pub_der == pub_der


def get_validity_period_from_pem_cert(pem: str):
    cert = load_pem_x509_certificate(pem.encode(), default_backend())
    return cert.not_valid_before, cert.not_valid_after


def datetime_to_X509time(datetime: datetime):
    return UTCTime.fromDateTime(datetime)
