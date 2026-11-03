# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Derive legacy and did:key CCF identity IDs without contacting a service."""

import hashlib
from enum import StrEnum

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.base import CertificatePublicKeyTypes


class IdentityIdFormat(StrEnum):
    """Supported formats for newly enrolled CCF identities."""

    SHA256 = "sha256"
    DID_KEY = "did:key"


_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_EC_CODECS = {
    "secp256r1": 0x1200,
    "secp384r1": 0x1201,
    "secp521r1": 0x1202,
}


def did_key_from_public_key(
    key: CertificatePublicKeyTypes,
) -> str:
    """Encode an existing NIST EC or 2048-16384-bit RSA key as a bare did:key.

    Raises TypeError for an unsupported key type, or ValueError for an
    unsupported curve or RSA key size.
    """
    if isinstance(key, ec.EllipticCurvePublicKey):
        if key.curve.name not in _EC_CODECS:
            raise ValueError(f"Unsupported did:key curve: {key.curve.name}")
        codec = _EC_CODECS[key.curve.name]
        raw = key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint,
        )
    elif isinstance(key, rsa.RSAPublicKey):
        if not 2048 <= key.key_size <= 16384:
            raise ValueError("did:key RSA keys must be between 2048 and 16384 bits")
        codec = 0x1205
        raw = key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.PKCS1
        )
    else:
        raise TypeError("Unsupported did:key public key type")

    # The supported multicodecs all have a two-byte, minimal varint.
    encoded = bytes([(codec & 0x7F) | 0x80, codec >> 7]) + raw
    value = int.from_bytes(encoded, "big")
    digits = []
    while value:
        value, digit = divmod(value, 58)
        digits.append(_BASE58[digit])
    return "did:key:z" + "".join(reversed(digits))


def identity_id_from_cert(
    cert_pem: str,
    id_format: IdentityIdFormat | str = IdentityIdFormat.SHA256,
) -> str:
    """Derive a member/user ID from a PEM certificate and enrollment format.

    Legacy IDs fingerprint the certificate; did:key IDs identify its public key.
    Raises ValueError for an invalid format, certificate, or unsupported curve
    or RSA size, and TypeError for an unsupported DID key type.
    """
    selected_format = IdentityIdFormat(id_format)
    cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    if selected_format == IdentityIdFormat.SHA256:
        return cert.fingerprint(hashes.SHA256()).hex()
    return did_key_from_public_key(cert.public_key())


def node_id_from_cert(
    cert_pem: str,
    id_format: IdentityIdFormat | str = IdentityIdFormat.SHA256,
) -> str:
    """Derive a node ID, whose legacy format fingerprints its public key.

    Raises ValueError for an invalid format, certificate, or unsupported curve
    or RSA size, and TypeError for an unsupported DID key type.
    """
    selected_format = IdentityIdFormat(id_format)
    if selected_format == IdentityIdFormat.DID_KEY:
        return identity_id_from_cert(cert_pem, selected_format)
    cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def main() -> None:
    """Print an identity ID for SDK and recovery-script users."""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", required=True, help="PEM certificate file")
    parser.add_argument(
        "--id-format", choices=list(IdentityIdFormat), default=IdentityIdFormat.SHA256
    )
    parser.add_argument("--node", action="store_true", help="Derive a node ID")
    args = parser.parse_args()
    with open(args.cert, encoding="ascii") as cert_file:
        cert = cert_file.read()
    derive = node_id_from_cert if args.node else identity_id_from_cert
    print(derive(cert, args.id_format))


if __name__ == "__main__":
    main()
