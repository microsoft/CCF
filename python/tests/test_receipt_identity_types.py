# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Unit tests for COSE receipts of CLASSICAL (EC) and PQ (ML-DSA) service
identities, and for the endorsements chains of previous service identities."""

from hashlib import sha256
from typing import Any

import cbor2
import ccf.cose
import ccf.receipt
import ccf.signatures
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CLAIM = sha256(b"test claim").digest()
LEAF: list[Any] = [sha256(b"write set").digest(), "ce:2.42", CLAIM]
LEAF_ROOT = sha256(LEAF[0] + sha256(LEAF[1].encode()).digest() + CLAIM).digest()
IAT = 1700000000
COSE_SIGN1_TAG = 18


def _mldsa():
    """Return the ML-DSA module, skipping the test without ML-DSA support."""
    mldsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")
    try:
        mldsa.MLDSA44PrivateKey.generate()
    except Exception as exc:
        pytest.skip(f"cryptography has no ML-DSA support: {exc}")
    return mldsa


def _ec_key():
    return ec.generate_private_key(ec.SECP384R1())


def _mldsa_key():
    return _mldsa().MLDSA65PrivateKey.generate()


KEY_FACTORIES = {"CLASSICAL": _ec_key, "PQ": _mldsa_key}


@pytest.fixture(params=list(KEY_FACTORIES))
def make_key(request):
    return KEY_FACTORIES[request.param]


def _alg(private_key) -> int:
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return -35
    return ccf.cose.COSE_ALG_ML_DSA_65


def _sign(private_key, to_be_signed: bytes) -> bytes:
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        r, s = utils.decode_dss_signature(
            private_key.sign(to_be_signed, ec.ECDSA(hashes.SHA384()))
        )
        return r.to_bytes(48, "big") + s.to_bytes(48, "big")
    return private_key.sign(to_be_signed)


def _spki(public_key) -> bytes:
    return public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def _sign1(private_key, protected, unprotected, payload, detached=True) -> bytes:
    protected_bytes = cbor2.dumps(protected)
    signature = _sign(
        private_key, cbor2.dumps(["Signature1", protected_bytes, b"", payload])
    )
    return cbor2.dumps(
        cbor2.CBORTag(
            COSE_SIGN1_TAG,
            [protected_bytes, unprotected, None if detached else payload, signature],
        )
    )


def _receipt(private_key, txid="2.150", alg=None) -> bytes:
    """Receipt of the transaction with LEAF, signed at txid"""
    protected = {
        1: _alg(private_key) if alg is None else alg,
        4: sha256(_spki(private_key.public_key())).hexdigest().encode("ascii"),
        15: {1: "service.example.com", 2: "ledger.signature", 6: IAT},
        ccf.cose.COSE_PHDR_VDS_LABEL: ccf.cose.COSE_PHDR_VDS_CCF_LEDGER_SHA256,
        "ccf.v1": {"txid": txid},
    }
    unprotected = {
        ccf.cose.COSE_PHDR_VDP_LABEL: {
            ccf.cose.COSE_RECEIPT_INCLUSION_PROOF_LABEL: [cbor2.dumps({1: LEAF, 2: []})]
        }
    }
    return _sign1(private_key, protected, unprotected, LEAF_ROOT)


def _endorsement(endorser, endorsed, begin: str, end: str | None) -> bytes:
    """Endorsement by the endorser private key of the endorsed one, which
    signed the transactions from begin to end"""
    claims = {"epoch.start.txid": begin}
    if end is not None:
        claims["epoch.end.txid"] = end
    protected = {1: _alg(endorser), 15: {6: IAT}, "ccf.v1": claims}
    return _sign1(endorser, protected, {}, _spki(endorsed.public_key()), detached=False)


def _chain(make_key):
    """Keys of three services, created at 2.1, 4.201 and 6.401, and the
    endorsements chain of the oldest one, newest first"""
    keys = [make_key() for _ in range(3)]
    endorsements = [
        _endorsement(keys[2], keys[1], "4.201", "4.400"),
        _endorsement(keys[1], keys[0], "2.1", "2.200"),
    ]
    return keys, endorsements


def test_receipt_verifies_with_the_key_of_its_identity_type(make_key):
    key = make_key()
    phdr = ccf.receipt.verify_cose(_receipt(key), key.public_key(), CLAIM)
    assert phdr["ccf.v1"]["txid"] == "2.150"


def test_receipt_rejects_keys_of_another_identity_type():
    ec_key = _ec_key()
    mldsa_key = _mldsa_key()
    for receipt, key in (
        (_receipt(mldsa_key), ec_key),
        (_receipt(ec_key), mldsa_key),
        (_receipt(mldsa_key), _mldsa_key()),
    ):
        with pytest.raises(ValueError, match="expected key"):
            ccf.receipt.verify_cose(receipt, key.public_key(), CLAIM)


def test_mldsa_receipt_rejects_invalid_signatures():
    key = _mldsa_key()
    receipt = _receipt(key)
    tampered = receipt[:-1] + bytes([receipt[-1] ^ 1])
    with pytest.raises(ccf.signatures.InvalidRootCoseSignatureException):
        ccf.receipt.verify_cose(tampered, key.public_key(), CLAIM)
    # Not the algorithm of the key's parameter set
    with pytest.raises(ccf.signatures.InvalidRootCoseSignatureException):
        ccf.receipt.verify_cose(
            _receipt(key, alg=ccf.cose.COSE_ALG_ML_DSA_44), key.public_key(), CLAIM
        )
    with pytest.raises(ValueError, match="Claim digest mismatch"):
        ccf.receipt.verify_cose(receipt, key.public_key(), b"x" * 32)


def test_verify_cose_sign1_mldsa():
    key = _mldsa_key()
    spki = _spki(key.public_key())
    protected = {1: ccf.cose.COSE_ALG_ML_DSA_65}
    embedded = _sign1(key, protected, {}, b"payload", detached=False)
    assert ccf.cose.verify_cose_sign1_mldsa(spki, embedded) == (
        protected,
        {},
        b"payload",
    )
    detached = _sign1(key, protected, {}, b"payload")
    assert ccf.cose.verify_cose_sign1_mldsa(spki, detached, b"payload")[2] == (
        b"payload"
    )
    with pytest.raises(ValueError, match="detached"):
        ccf.cose.verify_cose_sign1_mldsa(spki, detached)
    with pytest.raises(ValueError, match="must be detached"):
        ccf.cose.verify_cose_sign1_mldsa(spki, embedded, b"payload")
    with pytest.raises(ValueError, match="verification failed"):
        ccf.cose.verify_cose_sign1_mldsa(spki, detached, b"other payload")
    with pytest.raises(ValueError, match="alg"):
        ccf.cose.verify_cose_sign1_mldsa(
            spki, _sign1(key, {1: ccf.cose.COSE_ALG_ML_DSA_87}, {}, b"payload")
        )
    with pytest.raises(ValueError, match="expected key"):
        ccf.cose.verify_cose_sign1_mldsa(
            spki, _sign1(key, {**protected, 4: b"other"}, {}, b"payload"), b"payload"
        )
    with pytest.raises(TypeError):
        ccf.cose.verify_cose_sign1_mldsa(_spki(_ec_key().public_key()), embedded)

    pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    assert ccf.cose.verify_cose_sign1_with_key(pem, embedded)[2] == b"payload"


def test_mldsa_verification_does_not_need_cbor2_frozendict(monkeypatch):
    # cbor2 exports frozendict only before Python 3.15, which has a built-in one
    monkeypatch.delattr(cbor2, "frozendict", raising=False)
    keys = [_mldsa_key() for _ in range(2)]
    spki = _spki(keys[0].public_key())
    protected = {1: ccf.cose.COSE_ALG_ML_DSA_65}
    unprotected = {"note": {"nested": b"map"}}
    message = _sign1(keys[0], protected, unprotected, b"payload", False)
    assert ccf.cose.verify_cose_sign1_mldsa(spki, message) == (
        protected,
        unprotected,
        b"payload",
    )
    ccf.receipt.verify_cose(
        _receipt(keys[0]),
        keys[1].public_key(),
        CLAIM,
        [_endorsement(keys[1], keys[0], "2.1", "2.200")],
    )


def test_endorsements_chain_endorses_previous_service_keys(make_key):
    keys, endorsements = _chain(make_key)
    current = keys[2].public_key()

    key, begin, end = ccf.receipt.verify_cose_endorsements(endorsements, current)
    assert _spki(key) == _spki(keys[0].public_key())
    assert (str(begin), str(end)) == ("2.1", "2.200")

    key, begin, end = ccf.receipt.verify_cose_endorsements(endorsements[:1], current)
    assert _spki(key) == _spki(keys[1].public_key())
    assert (str(begin), str(end)) == ("4.201", "4.400")


def test_receipt_of_a_previous_service_verifies_with_its_endorsements(make_key):
    keys, endorsements = _chain(make_key)
    current = keys[2].public_key()

    ccf.receipt.verify_cose(_receipt(keys[0], "2.150"), current, CLAIM, endorsements)
    ccf.receipt.verify_cose(
        _receipt(keys[1], "4.300"), current, CLAIM, endorsements[:1]
    )

    with pytest.raises(ValueError, match="not in the epoch"):
        ccf.receipt.verify_cose(
            _receipt(keys[0], "4.300"), current, CLAIM, endorsements
        )
    with pytest.raises(ValueError, match="expected key"):
        ccf.receipt.verify_cose(
            _receipt(keys[1], "2.150"), current, CLAIM, endorsements
        )
    with pytest.raises(ValueError, match="Endorsement 0"):
        ccf.receipt.verify_cose(
            _receipt(keys[0], "2.150"), keys[1].public_key(), CLAIM, endorsements
        )


def test_endorsements_chain_must_be_connected(make_key):
    keys, endorsements = _chain(make_key)
    current = keys[2].public_key()

    with pytest.raises(ValueError, match="must not be empty"):
        ccf.receipt.verify_cose_endorsements([], current)
    with pytest.raises(ValueError, match="Endorsement 0"):
        ccf.receipt.verify_cose_endorsements(endorsements[::-1], current)
    with pytest.raises(ValueError, match="does not end just before"):
        ccf.receipt.verify_cose_endorsements(
            [endorsements[0], _endorsement(keys[1], keys[0], "2.1", "2.199")],
            current,
        )
    # A recovery starts two views after the end of the previous epoch
    with pytest.raises(ValueError, match="does not end just before"):
        ccf.receipt.verify_cose_endorsements(
            [endorsements[0], _endorsement(keys[1], keys[0], "2.1", "3.200")],
            current,
        )
    with pytest.raises(ValueError, match="is empty"):
        ccf.receipt.verify_cose_endorsements(
            [_endorsement(keys[2], keys[1], "4.400", "4.201")], current
        )
    with pytest.raises(ValueError, match="epoch.end.txid"):
        ccf.receipt.verify_cose_endorsements(
            [_endorsement(keys[2], keys[2], "6.401", None)], current
        )


def test_endorsements_must_be_a_sequence_of_messages(make_key):
    keys, endorsements = _chain(make_key)
    current = keys[2].public_key()
    for message in (endorsements[0], bytearray(endorsements[0]), b""):
        # A single message, which the annotation of endorsements excludes
        single: Any = message
        with pytest.raises(TypeError, match="sequence of COSE Sign1 messages"):
            ccf.receipt.verify_cose_endorsements(single, current)
        with pytest.raises(TypeError, match="sequence of COSE Sign1 messages"):
            ccf.receipt.verify_cose(_receipt(keys[1], "4.300"), current, CLAIM, single)
