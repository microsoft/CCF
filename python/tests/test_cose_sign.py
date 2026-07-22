# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import base64
import datetime

import cbor2
import ccf.cose
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
import cwt
import cwt.enums
import cwt.utils


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
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
        )
        .sign(priv, hash_algo(priv))
    )
    return cert.public_bytes(Encoding.PEM).decode("ascii")


@pytest.mark.parametrize("curve", [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()])
def test_create_cose_sign1_finish(curve):
    """
    Check create_cose_sign1_finish() produces the same output when passed
    a signature as create_cose_sign1().
    """
    priv = make_private_key(curve)
    priv_pem, _pub_pem = make_pem_pair(priv)
    cert = make_self_signed_cert(priv, "example.com")

    payload = b"Hello World"

    cose_sign1 = ccf.cose.create_cose_sign1(payload, priv_pem, cert)

    _, _, _, sig = cbor2.loads(cose_sign1).value
    b64_sig = base64.urlsafe_b64encode(sig)

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


def make_cose_endorsement(signer, payload_key, begin: str, end: str) -> bytes:
    signer_priv_pem, signer_pub_pem = make_pem_pair(signer)
    kid = ccf.cose.key_fingerprint_from_key(signer_pub_pem)
    cose_key = cwt.COSEKey.from_pem(signer_priv_pem, kid=kid)
    protected = cwt.utils.ResolvedHeader(
        {
            int(cwt.COSEHeaders.KID): kid.encode("utf-8"),
            ccf.cose.CCF_V1_LABEL: {
                ccf.cose.CCF_ENDORSEMENT_RANGE_BEGIN: begin,
                ccf.cose.CCF_ENDORSEMENT_RANGE_END: end,
            },
        }
    )
    payload = payload_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return cwt.COSE.new(
        alg_auto_inclusion=True, deterministic_header=True
    ).encode_and_sign(payload, cose_key, protected=protected)


def test_cose_endorsement_sidecar_chain():
    identities = [make_private_key(ec.SECP384R1()) for _ in range(3)]
    oldest = make_cose_endorsement(
        identities[1], identities[0].public_key(), "2.1", "4.100"
    )
    newest = make_cose_endorsement(
        identities[2], identities[1].public_key(), "6.101", "8.200"
    )
    endorsements = [newest, oldest]

    serialized = ccf.cose.serialize_cose_endorsements(endorsements)
    assert ccf.cose.deserialize_cose_endorsements(serialized) == endorsements

    snapshot_key = ccf.cose.verify_cose_endorsements(
        endorsements, identities[2].public_key(), snapshot_seqno=50
    )
    assert snapshot_key.public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    ) == identities[0].public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )

    with pytest.raises(ValueError):
        ccf.cose.verify_cose_endorsements(
            list(reversed(endorsements)),
            identities[2].public_key(),
            snapshot_seqno=50,
        )

    tampered = [bytearray(newest), oldest]
    tampered[0][-1] ^= 0xFF
    with pytest.raises(ValueError):
        ccf.cose.verify_cose_endorsements(
            [bytes(tampered[0]), tampered[1]],
            identities[2].public_key(),
            snapshot_seqno=50,
        )

    with pytest.raises(ValueError, match="does not cover"):
        ccf.cose.verify_cose_endorsements(
            endorsements, identities[2].public_key(), snapshot_seqno=1000
        )


def test_cose_endorsement_sidecar_encoding_is_strict():
    with pytest.raises(ValueError, match="CBOR array"):
        ccf.cose.deserialize_cose_endorsements(cbor2.dumps({"not": "an array"}))
    with pytest.raises(ValueError, match="Trailing data"):
        ccf.cose.deserialize_cose_endorsements(cbor2.dumps([]) + b"\x00")
