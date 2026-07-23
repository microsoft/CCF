# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import base64
import datetime
import hashlib
import os
import subprocess
import sys
from pathlib import Path
from typing import Tuple

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
import ccf.ledger
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


def make_manually_signed_cose_sign1(
    signer: ec.EllipticCurvePrivateKey,
    payload: bytes,
    protected: dict,
    unprotected: dict,
    detached: bool,
) -> bytes:
    protected_encoded = cbor2.dumps(protected)
    to_be_signed = cbor2.dumps(["Signature1", protected_encoded, b"", payload])
    der_signature = signer.sign(to_be_signed, ec.ECDSA(hash_algo(signer)))
    r, s = utils.decode_dss_signature(der_signature)
    num_bytes = (signer.key_size + 7) // 8
    raw_signature = i2osp(r, num_bytes) + i2osp(s, num_bytes)
    return cbor2.dumps(
        cbor2.CBORTag(
            cwt.const.COSE_TYPE_TO_TAG[cwt.const.COSETypes.SIGN1],
            [
                protected_encoded,
                unprotected,
                None if detached else payload,
                raw_signature,
            ],
        )
    )


def make_cose_receipt(
    signer: ec.EllipticCurvePrivateKey,
    claim_digest: bytes,
    path: list[list[bool | bytes]],
    include_protected_algorithm: bool = True,
    protected_algorithm: int | bool | None = None,
    unprotected_algorithm: int | bool | None = None,
    verifiable_data_structure: int | bool = (ccf.cose.COSE_PHDR_VDS_CCF_LEDGER_SHA256),
) -> bytes:
    _, signer_pub_pem = make_pem_pair(signer)
    kid = ccf.cose.key_fingerprint_from_key(signer_pub_pem)
    protected = {
        int(cwt.COSEHeaders.KID): kid.encode("utf-8"),
        ccf.cose.COSE_PHDR_VDS_LABEL: verifiable_data_structure,
    }
    if include_protected_algorithm:
        protected[int(cwt.COSEHeaders.ALG)] = (
            ccf.cose.default_algorithm_for_key(signer.public_key())
            if protected_algorithm is None
            else protected_algorithm
        )

    write_set_digest = hashlib.sha256(b"write set").digest()
    commit_evidence = "ce:2.1"
    proof = cbor2.dumps(
        {
            ccf.cose.CCF_PROOF_LEAF_LABEL: [
                write_set_digest,
                commit_evidence,
                claim_digest,
            ],
            ccf.cose.CCF_PROOF_PATH_LABEL: path,
        }
    )
    unprotected: dict[int, object] = {
        ccf.cose.COSE_PHDR_VDP_LABEL: {
            ccf.cose.COSE_RECEIPT_INCLUSION_PROOF_LABEL: [proof]
        }
    }
    if unprotected_algorithm is not None:
        unprotected[int(cwt.COSEHeaders.ALG)] = unprotected_algorithm
    root = hashlib.sha256(
        write_set_digest
        + hashlib.sha256(commit_evidence.encode()).digest()
        + claim_digest
    ).digest()

    return make_manually_signed_cose_sign1(
        signer,
        root,
        protected,
        unprotected,
        detached=True,
    )


def make_manual_cose_endorsement(
    signer: ec.EllipticCurvePrivateKey,
    payload_key: ec.EllipticCurvePublicKey,
    include_protected_algorithm: bool = True,
    protected_algorithm: int | bool | None = None,
    unprotected_algorithm: int | bool | None = None,
) -> bytes:
    _, signer_pub_pem = make_pem_pair(signer)
    kid = ccf.cose.key_fingerprint_from_key(signer_pub_pem)
    protected = {
        int(cwt.COSEHeaders.KID): kid.encode("utf-8"),
        ccf.cose.CCF_V1_LABEL: {
            ccf.cose.CCF_ENDORSEMENT_RANGE_BEGIN: "2.1",
            ccf.cose.CCF_ENDORSEMENT_RANGE_END: "4.100",
        },
    }
    if include_protected_algorithm:
        protected[int(cwt.COSEHeaders.ALG)] = (
            ccf.cose.default_algorithm_for_key(signer.public_key())
            if protected_algorithm is None
            else protected_algorithm
        )
    unprotected = {}
    if unprotected_algorithm is not None:
        unprotected[int(cwt.COSEHeaders.ALG)] = unprotected_algorithm
    payload = payload_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return make_manually_signed_cose_sign1(
        signer, payload, protected, unprotected, detached=False
    )


def test_verify_cose_receipt_with_empty_merkle_path():
    signer = make_private_key(ec.SECP384R1())
    claim_digest = hashlib.sha256(b"snapshot").digest()
    receipt = make_cose_receipt(signer, claim_digest, path=[])

    protected = ccf.cose.verify_receipt(receipt, signer.public_key(), claim_digest)
    assert (
        protected[ccf.cose.COSE_PHDR_VDS_LABEL]
        == ccf.cose.COSE_PHDR_VDS_CCF_LEDGER_SHA256
    )

    endorsed_protected = ccf.cose.verify_receipt_with_endorsements(
        receipt,
        signer.public_key(),
        claim_digest,
        endorsements=[],
        snapshot_seqno=1,
    )
    assert endorsed_protected == protected


def test_cose_receipt_rejects_invalid_signature():
    signer = make_private_key(ec.SECP384R1())
    claim_digest = hashlib.sha256(b"snapshot").digest()
    receipt = bytearray(make_cose_receipt(signer, claim_digest, path=[]))
    receipt[-1] ^= 0xFF

    with pytest.raises(ValueError, match="signature verification failed"):
        ccf.cose.verify_receipt(bytes(receipt), signer.public_key(), claim_digest)


@pytest.mark.parametrize("algorithm", [True, 0, 5, -7, 999999])
def test_cose_receipt_rejects_wrong_or_boolean_algorithm(algorithm):
    signer = make_private_key(ec.SECP384R1())
    claim_digest = hashlib.sha256(b"snapshot").digest()
    receipt = make_cose_receipt(
        signer, claim_digest, path=[], protected_algorithm=algorithm
    )

    with pytest.raises(ValueError, match="signing algorithm"):
        ccf.cose.verify_receipt(receipt, signer.public_key(), claim_digest)


def test_cose_receipt_rejects_missing_or_unprotected_algorithm():
    signer = make_private_key(ec.SECP384R1())
    claim_digest = hashlib.sha256(b"snapshot").digest()

    missing = make_cose_receipt(
        signer,
        claim_digest,
        path=[],
        include_protected_algorithm=False,
    )
    with pytest.raises(ValueError, match="signing algorithm"):
        ccf.cose.verify_receipt(missing, signer.public_key(), claim_digest)

    expected_algorithm = ccf.cose.default_algorithm_for_key(signer.public_key())
    for unprotected_algorithm in (0, expected_algorithm):
        duplicate = make_cose_receipt(
            signer,
            claim_digest,
            path=[],
            unprotected_algorithm=unprotected_algorithm,
        )
        with pytest.raises(ValueError, match="unprotected headers"):
            ccf.cose.verify_receipt(duplicate, signer.public_key(), claim_digest)


def test_cose_receipt_rejects_boolean_vds():
    signer = make_private_key(ec.SECP384R1())
    claim_digest = hashlib.sha256(b"snapshot").digest()
    receipt = make_cose_receipt(
        signer,
        claim_digest,
        path=[],
        verifiable_data_structure=True,
    )

    with pytest.raises(ValueError, match="structure type must be an integer"):
        ccf.cose.verify_receipt(receipt, signer.public_key(), claim_digest)


def test_manual_cose_endorsement_accepts_expected_algorithm():
    signer = make_private_key(ec.SECP384R1())
    endorsed = make_private_key(ec.SECP384R1())
    endorsement = make_manual_cose_endorsement(signer, endorsed.public_key())

    verified_key = ccf.cose.verify_cose_endorsements(
        [endorsement], signer.public_key(), snapshot_seqno=50
    )
    assert verified_key.public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    ) == endorsed.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )


@pytest.mark.parametrize("algorithm", [True, 0, 5, -7, 999999])
def test_cose_endorsement_rejects_wrong_or_boolean_algorithm(algorithm):
    signer = make_private_key(ec.SECP384R1())
    endorsed = make_private_key(ec.SECP384R1())
    endorsement = make_manual_cose_endorsement(
        signer,
        endorsed.public_key(),
        protected_algorithm=algorithm,
    )

    with pytest.raises(ValueError, match="signing algorithm"):
        ccf.cose.verify_cose_endorsements(
            [endorsement], signer.public_key(), snapshot_seqno=50
        )


def test_cose_endorsement_rejects_missing_or_unprotected_algorithm():
    signer = make_private_key(ec.SECP384R1())
    endorsed = make_private_key(ec.SECP384R1())

    missing = make_manual_cose_endorsement(
        signer,
        endorsed.public_key(),
        include_protected_algorithm=False,
    )
    with pytest.raises(ValueError, match="signing algorithm"):
        ccf.cose.verify_cose_endorsements(
            [missing], signer.public_key(), snapshot_seqno=50
        )

    expected_algorithm = ccf.cose.default_algorithm_for_key(signer.public_key())
    for unprotected_algorithm in (0, expected_algorithm):
        duplicate = make_manual_cose_endorsement(
            signer,
            endorsed.public_key(),
            unprotected_algorithm=unprotected_algorithm,
        )
        with pytest.raises(ValueError, match="unprotected headers"):
            ccf.cose.verify_cose_endorsements(
                [duplicate], signer.public_key(), snapshot_seqno=50
            )


def test_receipt_verification_rejects_empty_proofs_under_optimization():
    python_src = str(Path(__file__).parents[1] / "src")
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        path for path in (python_src, env.get("PYTHONPATH")) if path
    )
    script = """
import cbor2
import cwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import ccf.cose

key = ec.generate_private_key(ec.SECP384R1())
public_pem = key.public_key().public_bytes(
    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
).decode("ascii")
kid = ccf.cose.key_fingerprint_from_key(public_pem).encode("utf-8")
protected = cbor2.dumps(
    {
        int(cwt.COSEHeaders.ALG): ccf.cose.default_algorithm_for_key(
            key.public_key()
        ),
        int(cwt.COSEHeaders.KID): kid,
        ccf.cose.COSE_PHDR_VDS_LABEL:
            ccf.cose.COSE_PHDR_VDS_CCF_LEDGER_SHA256,
    }
)
fabricated = cbor2.dumps(
    cbor2.CBORTag(
        cwt.const.COSE_TYPE_TO_TAG[cwt.const.COSETypes.SIGN1],
        [
            protected,
            {
                ccf.cose.COSE_PHDR_VDP_LABEL: {
                    ccf.cose.COSE_RECEIPT_INCLUSION_PROOF_LABEL: []
                }
            },
            None,
            b"\\x00" * 96,
        ],
    )
)

try:
    ccf.cose.verify_receipt_with_endorsements(
        fabricated,
        key.public_key(),
        b"\\x00" * 32,
        endorsements=[],
        snapshot_seqno=1,
    )
except ValueError as error:
    if str(error) != "At least one inclusion proof is required":
        raise
    print("rejected")
else:
    raise SystemExit("fabricated unsigned receipt was accepted")
"""
    result = subprocess.run(
        [sys.executable, "-O", "-c", script],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "rejected"


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
        ccf.cose.deserialize_cose_endorsements(
            ccf.cose.serialize_cose_endorsements([b"x" * 64]) + b"\x00"
        )


def test_cose_endorsement_sidecar_resource_limits(tmp_path):
    too_many = b"\x9a\x00\x0f\x42\x40"
    with pytest.raises(ValueError, match="between 1 and"):
        ccf.cose.deserialize_cose_endorsements(too_many)

    with pytest.raises(ValueError, match="between 1 and"):
        ccf.cose.deserialize_cose_endorsements(b"\x80")
    with pytest.raises(ValueError, match="between 1 and"):
        ccf.cose.serialize_cose_endorsements([])
    with pytest.raises(ValueError, match="too small"):
        ccf.cose.deserialize_cose_endorsements(b"\x81\x40")
    with pytest.raises(ValueError, match="too small"):
        ccf.cose.serialize_cose_endorsements([b"x"])
    with pytest.raises(ValueError, match="CBOR array"):
        ccf.cose.deserialize_cose_endorsements(b"\x9f\xff")

    nested = cbor2.dumps(
        [
            [b""] * ccf.cose.MAX_SNAPSHOT_ENDORSEMENTS_COUNT
            for _ in range(ccf.cose.MAX_SNAPSHOT_ENDORSEMENTS_COUNT)
        ]
    )
    with pytest.raises(ValueError, match="byte strings"):
        ccf.cose.deserialize_cose_endorsements(nested)

    oversized_endorsement = b"\x00" * (ccf.cose.MAX_SNAPSHOT_ENDORSEMENT_SIZE + 1)
    with pytest.raises(ValueError, match="too large"):
        ccf.cose.serialize_cose_endorsements([oversized_endorsement])
    with pytest.raises(ValueError, match="too large"):
        ccf.cose.deserialize_cose_endorsements(cbor2.dumps([oversized_endorsement]))

    maximum_endorsement = b"\x00" * ccf.cose.MAX_SNAPSHOT_ENDORSEMENT_SIZE
    with pytest.raises(ValueError, match="payload is too large"):
        ccf.cose.serialize_cose_endorsements([maximum_endorsement] * 5)
    with pytest.raises(ValueError, match="payload is too large"):
        ccf.cose.deserialize_cose_endorsements(cbor2.dumps([maximum_endorsement] * 5))

    oversized_path = tmp_path / "oversized.endorsements"
    oversized_path.write_bytes(b"\x00" * (ccf.cose.MAX_SNAPSHOT_ENDORSEMENTS_SIZE + 1))
    with pytest.raises(ValueError, match="sidecar .* is too large"):
        ccf.ledger.read_snapshot_endorsements(str(oversized_path))
