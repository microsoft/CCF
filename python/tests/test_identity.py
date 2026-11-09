# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import hashlib
import subprocess
from pathlib import Path

import ccf.identity
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)
from test_cose_sign import make_self_signed_cert


@pytest.mark.parametrize("curve", ["secp256r1", "secp384r1"])
@pytest.mark.parametrize("public_key_only", [False, True])
@pytest.mark.parametrize("encryption_key", [False, True])
def test_keygenerator(tmp_path, curve, public_key_only, encryption_key):
    script = Path(__file__).resolve().parents[1] / "utils" / "keygenerator.sh"
    args = [str(script), "--name", "member0", "--curve", curve]
    if public_key_only:
        args += ["--public-key-only"]
    if encryption_key:
        args += ["--gen-enc-key"]
    subprocess.run(args, cwd=tmp_path, check=True, capture_output=True)

    identity_key = load_pem_private_key(
        (tmp_path / "member0_privk.pem").read_bytes(), password=None
    )
    cert_path = tmp_path / "member0_cert.pem"
    public_key_path = tmp_path / "member0_pubk.pem"
    assert cert_path.exists() == (not public_key_only)
    assert public_key_path.exists() == public_key_only
    identity_public_key = (
        load_pem_public_key(public_key_path.read_bytes())
        if public_key_only
        else x509.load_pem_x509_certificate(cert_path.read_bytes()).public_key()
    )
    assert ccf.identity.did_key_from_public_key(identity_public_key) == (
        ccf.identity.did_key_from_public_key(identity_key.public_key())
    )
    enc_private_path = tmp_path / "member0_enc_privk.pem"
    enc_public_path = tmp_path / "member0_enc_pubk.pem"
    assert enc_private_path.exists() == encryption_key
    assert enc_public_path.exists() == encryption_key
    if encryption_key:
        enc_private = load_pem_private_key(enc_private_path.read_bytes(), password=None)
        enc_public = load_pem_public_key(enc_public_path.read_bytes())
        assert isinstance(enc_private, rsa.RSAPrivateKey)
        assert isinstance(enc_public, rsa.RSAPublicKey)
        assert enc_private.public_key().public_numbers() == enc_public.public_numbers()


@pytest.mark.parametrize("curve", [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()])
def test_certificate_replacement(curve):
    key = ec.generate_private_key(curve)
    first = make_self_signed_cert(key, "first")
    replacement = make_self_signed_cert(key, "replacement")
    assert ccf.identity.identity_id_from_cert(first) != (
        ccf.identity.identity_id_from_cert(replacement)
    )
    did = ccf.identity.identity_id_from_cert(first, "did:key")
    assert did.startswith("did:key:z")
    assert did == ccf.identity.identity_id_from_cert(replacement, "did:key")
    assert did == ccf.identity.node_id_from_cert(first, "did:key")
    assert ccf.identity.identity_id_from_cert(first) == (
        x509.load_pem_x509_certificate(first.encode())
        .fingerprint(hashes.SHA256())
        .hex()
    )
    der = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    assert ccf.identity.node_id_from_cert(first) == hashlib.sha256(der).hexdigest()
    with pytest.raises(ValueError):
        ccf.identity.identity_id_from_cert(first, "unknown")


def test_supported_key_types():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    assert ccf.identity.did_key_from_public_key(key).startswith("did:key:z")
    with pytest.raises(TypeError, match="Unsupported"):
        ccf.identity.did_key_from_public_key(
            ed25519.Ed25519PrivateKey.generate().public_key()
        )
    with pytest.raises(ValueError, match="2048"):
        ccf.identity.did_key_from_public_key(
            rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()
        )


@pytest.mark.parametrize(
    "curve,point,did",
    [
        (
            ec.SECP256R1(),
            "038a0ac59a2d3086e8a12a78fd4773a6d52a0ca61ef6c1419e15a05bcc6dafce7b",
            "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
        ),
        (
            ec.SECP384R1(),
            "03080fa23681c383594bf29bd7dddd6ebc4c7355f0b3ed19fab56efcd546fc2b932b0dfd8830fc8bd114c389a2c70b5253",
            "did:key:z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54",
        ),
    ],
)
def test_published_did_key_vectors(curve, point, did):
    # Public test vectors from https://w3c-ccg.github.io/did-key-spec/.
    key = ec.EllipticCurvePublicKey.from_encoded_point(curve, bytes.fromhex(point))
    assert ccf.identity.did_key_from_public_key(key) == did


@pytest.mark.parametrize("curve", [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()])
def test_did_key_roundtrip_without_certificate(curve):
    key = ec.generate_private_key(curve).public_key()
    did = ccf.identity.did_key_from_public_key(key)
    decoded = ccf.identity.public_key_from_did_key(did)
    assert isinstance(decoded, ec.EllipticCurvePublicKey)
    assert decoded.public_numbers() == key.public_numbers()
    for invalid in [did + "#fragment", did + "?query", "did:key:z1", did[:-1]]:
        with pytest.raises(ValueError):
            ccf.identity.public_key_from_did_key(invalid)
