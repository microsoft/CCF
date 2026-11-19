# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Derive did:key CCF identity IDs without contacting a service."""

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_EC_CODECS = {
    "secp256r1": 0x1200,
    "secp384r1": 0x1201,
    "secp521r1": 0x1202,
}


def did_key_from_public_key(
    key: PublicKeyTypes,
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
    digits: list[str] = []
    while value:
        value, digit = divmod(value, 58)
        digits.append(_BASE58[digit])
    return "did:key:z" + "".join(reversed(digits))


def public_key_from_did_key(
    did_key: str,
) -> ec.EllipticCurvePublicKey | rsa.RSAPublicKey:
    """Decode a supported base58-btc did:key to its public key.

    Raises ValueError for malformed or unsupported identities, including the
    base64url (u) multibase form and any DID that is not the deterministic
    encoding of its public key.
    """
    if did_key.startswith("did:key:u"):
        raise ValueError("Only base58-btc (z) multibase did:key IDs are supported")
    if not did_key.startswith("did:key:z") or not 9 < len(did_key) <= 3000:
        raise ValueError("Invalid did:key")
    value = 0
    for digit in did_key[9:]:
        if digit not in _BASE58:
            raise ValueError("Invalid did:key alphabet")
        value = value * 58 + _BASE58.index(digit)
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if len(raw) < 3 or raw[1] != 0x24:
        raise ValueError("Invalid did:key multicodec")
    curves = {
        0x80: ec.SECP256R1(),
        0x81: ec.SECP384R1(),
        0x82: ec.SECP521R1(),
    }
    if raw[0] in curves:
        key = ec.EllipticCurvePublicKey.from_encoded_point(curves[raw[0]], raw[2:])
    elif raw[0] == 0x85:
        key = serialization.load_der_public_key(raw[2:])
        if not isinstance(key, rsa.RSAPublicKey):
            raise ValueError("Invalid did:key RSA key")
    else:
        raise ValueError("Unsupported did:key multicodec")
    if did_key_from_public_key(key) != did_key:
        raise ValueError("did:key is not the deterministic encoding of its public key")
    return key


def main() -> None:
    """Print the did:key of a public key, or of the public key in a certificate."""
    import argparse

    parser = argparse.ArgumentParser(description=main.__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--public-key", help="PEM public key file")
    source.add_argument(
        "--cert", help="PEM certificate file, to migrate a legacy identity"
    )
    args = parser.parse_args()
    if args.public_key:
        with open(args.public_key, "rb") as key_file:
            key = serialization.load_pem_public_key(key_file.read())
    else:
        with open(args.cert, "rb") as cert_file:
            key = x509.load_pem_x509_certificate(cert_file.read()).public_key()
    print(did_key_from_public_key(key))


if __name__ == "__main__":
    main()
