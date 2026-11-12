# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import base64
import datetime
import json
import subprocess
import sys

import cbor2
import ccf.cose
import ccf.identity
import cwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def make_private_key(curve: ec.EllipticCurve):
    return ec.generate_private_key(curve=curve)


def make_pem_pair(priv) -> tuple[str, str]:
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
    return bytes.fromhex("".join(f"{x:02x}" for x in digits[::-1]))


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
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30)
        )
        .sign(priv, hash_algo(priv))
    )
    return cert.public_bytes(Encoding.PEM).decode("ascii")


@pytest.mark.parametrize("curve", [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()])
@pytest.mark.parametrize("signature_as_text", [False, True])
def test_create_cose_sign1_finish(curve, signature_as_text: bool):
    """
    Check create_cose_sign1_finish() produces the same output when passed
    a signature as create_cose_sign1().
    """
    priv = make_private_key(curve)
    priv_pem, _pub_pem = make_pem_pair(priv)
    cert = make_self_signed_cert(priv, "example.com")

    payload = b"Hello World"

    cose_sign1 = ccf.cose.create_cose_sign1(payload, priv_pem, cert)

    protected, _, _, sig = cbor2.loads(cose_sign1).value
    assert cbor2.loads(protected)[int(cwt.COSEHeaders.KID)] == (
        ccf.identity.identity_id_from_cert(cert).encode()
    )
    b64_sig: str | bytes = base64.urlsafe_b64encode(sig)
    if signature_as_text:
        b64_sig = b64_sig.decode("ascii")

    ccf.cose.verify_cose_sign1_with_cert(cert.encode(), cose_sign1, use_key=False)
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
    ccf.cose.verify_cose_sign1_with_cert(
        cert.encode(), finished_cose_sign1, use_key=False
    )


@pytest.mark.parametrize("curve", [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()])
def test_certificate_free_signing(curve):
    private_key = make_private_key(curve)
    private_pem, _ = make_pem_pair(private_key)
    did = ccf.identity.did_key_from_public_key(private_key.public_key())
    payload = b"Certificate-free governance"
    signed = ccf.cose.create_cose_sign1(payload, private_pem, did_key=did)
    protected, _, verified = ccf.cose.verify_cose_sign1_with_did_key(did, signed)
    assert protected[int(cwt.COSEHeaders.KID)] == did.encode("ascii")
    assert verified == payload

    prepared = ccf.cose.create_cose_sign1_prepare(payload, did_key=did)
    digest = base64.b64decode(prepared["value"])
    signature = private_key.sign(
        digest, ec.ECDSA(utils.Prehashed(hash_algo(private_key)))
    )
    r, s = utils.decode_dss_signature(signature)
    size = (private_key.key_size + 7) // 8
    raw = i2osp(r, size) + i2osp(s, size)
    finished = ccf.cose.create_cose_sign1_finish(
        payload, signature=base64.urlsafe_b64encode(raw), did_key=did
    )
    assert ccf.cose.verify_cose_sign1_with_did_key(did, finished)[2] == payload

    wrong_private_pem, _ = make_pem_pair(make_private_key(curve))
    with pytest.raises(ValueError, match="does not match"):
        ccf.cose.create_cose_sign1(payload, wrong_private_pem, did_key=did)
    with pytest.raises(ValueError, match="must not be combined"):
        ccf.cose.create_cose_sign1(
            payload,
            private_pem,
            make_self_signed_cert(private_key, "test"),
            did_key=did,
        )
    cert = make_self_signed_cert(private_key, "test")
    with pytest.raises(ValueError, match="must not be combined"):
        ccf.cose.create_cose_sign1_prepare(payload, cert, did_key=did)
    with pytest.raises(ValueError, match="must not be combined"):
        ccf.cose.create_cose_sign1_finish(
            payload, cert, base64.urlsafe_b64encode(raw), did_key=did
        )


@pytest.mark.parametrize("curve", [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()])
def test_certificate_free_signing_cli(curve, tmp_path):
    private_key = make_private_key(curve)
    private_pem, _ = make_pem_pair(private_key)
    did = ccf.identity.did_key_from_public_key(private_key.public_key())
    key_file = tmp_path / "identity_key.pem"
    key_file.write_text(private_pem, encoding="ascii")
    payload = b"Certificate-free CLI request"
    common_args = [
        "--signing-did-key",
        did,
        "--content",
        "-",
        "--ccf-gov-msg-type",
        "proposal",
        "--ccf-gov-msg-created_at",
        "2025-01-01T00:00:00+00:00",
    ]

    def run_cli(command, *extra_args):
        return subprocess.run(
            [
                sys.executable,
                "-c",
                f"from ccf.cose import {command}_cli; {command}_cli()",
                *common_args,
                *extra_args,
            ],
            input=payload,
            capture_output=True,
            check=True,
        )

    result = run_cli("sign", "--signing-key", str(key_file))
    protected, _, verified = ccf.cose.verify_cose_sign1_with_did_key(did, result.stdout)
    assert protected[int(cwt.COSEHeaders.KID)] == did.encode("ascii")
    assert protected["ccf.gov.msg.type"] == "proposal"
    assert verified == payload
    prepared = json.loads(run_cli("prepare").stdout)
    signature = private_key.sign(
        base64.b64decode(prepared["value"]),
        ec.ECDSA(utils.Prehashed(hash_algo(private_key))),
    )
    r, s = utils.decode_dss_signature(signature)
    size = (private_key.key_size + 7) // 8
    raw = i2osp(r, size) + i2osp(s, size)
    signature_file = tmp_path / "signature.json"
    signature_file.write_text(
        json.dumps({"value": base64.urlsafe_b64encode(raw).decode("ascii")}),
        encoding="ascii",
    )
    finished = run_cli("finish", "--signature", str(signature_file))
    protected, _, verified = ccf.cose.verify_cose_sign1_with_did_key(
        did, finished.stdout
    )
    assert protected[int(cwt.COSEHeaders.KID)] == did.encode("ascii")
    assert verified == payload


@pytest.mark.parametrize("command", ["sign", "prepare", "finish"])
def test_cli_rejects_certificate_did_format(command):
    args = [
        sys.executable,
        "-c",
        f"from ccf.cose import {command}_cli; {command}_cli()",
        "--signing-cert",
        "unused_cert.pem",
        "--content",
        "-",
        "--ccf-gov-msg-type",
        "proposal",
        "--ccf-gov-msg-created_at",
        "2025-01-01T00:00:00+00:00",
        "--identity-id-format",
        "did:key",
    ]
    if command == "sign":
        args += ["--signing-key", "unused_key.pem"]
    elif command == "finish":
        args += ["--signature", "unused_signature.json"]
    result = subprocess.run(args, input=b"", capture_output=True, check=False)
    assert result.returncode == 2
    assert b"unrecognized arguments: --identity-id-format did:key" in result.stderr
