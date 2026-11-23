# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import base64
import subprocess
import sys
from pathlib import Path

import ccf.identity
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)


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
    source = (
        ["--public-key", str(public_key_path)]
        if public_key_only
        else ["--cert", str(cert_path)]
    )
    cli = subprocess.run(
        [sys.executable, "-m", "ccf.identity", *source],
        check=True,
        capture_output=True,
        text=True,
    )
    assert cli.stdout.strip() == (
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


def test_unsupported_key_types():
    for key in (
        rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key(),
        ed25519.Ed25519PrivateKey.generate().public_key(),
    ):
        with pytest.raises(TypeError, match="Unsupported"):
            ccf.identity.did_key_from_public_key(key)
    with pytest.raises(ValueError, match="Unsupported"):
        ccf.identity.did_key_from_public_key(
            ec.generate_private_key(ec.SECP256K1()).public_key()
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


def test_did_key_base64url_multibase_is_rejected():
    # The did:key identifier syntax also allows base64url (u) multibase values,
    # but CCF only accepts the base58-btc (z) form that it produces.
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    point = key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    encoded = base64.urlsafe_b64encode(b"\x80\x24" + point).rstrip(b"=")
    with pytest.raises(ValueError, match="base58-btc"):
        ccf.identity.public_key_from_did_key("did:key:u" + encoded.decode())
    assert ccf.identity.did_key_from_public_key(key).startswith("did:key:z")
