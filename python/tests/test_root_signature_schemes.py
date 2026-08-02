# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Unit tests for the root-signature verifiers in :mod:`ccf.signatures`."""

import base64
import datetime
import json

import pytest
from ccf.signatures import (
    COSE_SIGNATURE_TX_TABLE_NAME,
    ROOT_SIGNATURE_VERIFIERS,
    SIGNATURE_TABLE_NAMES,
    SIGNATURE_TX_TABLE_NAME,
    WELL_KNOWN_SINGLETON_TABLE_KEY,
    InvalidRootException,
    InvalidRootSignatureException,
    RootSignatureContext,
    UntrustedNodeException,
    is_signature_transaction,
    verify_all_root_signatures,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import NameOID

ROOT = b"\x5a" * 32


def _ec_identity():
    """A throwaway signing identity, as ``(private key, PEM certificate)``."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-node")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(serialization.Encoding.PEM)


KEY, CERT = _ec_identity()


def _raw_tx(root=ROOT, sign=True, view=2, seqno=7, cert=None):
    """A signature transaction carrying a raw entry, genuinely signed over
    ``root`` unless ``sign`` is False."""
    sig = KEY.sign(root, ec.ECDSA(utils.Prehashed(hashes.SHA256()))) if sign else b"sig"
    entry = {
        "view": view,
        "seqno": seqno,
        "node": "node0",
        "root": root.hex(),
        "sig": base64.b64encode(sig).decode(),
    }
    if cert is not None:
        entry["cert"] = cert.decode()
    return {
        SIGNATURE_TX_TABLE_NAME: {
            WELL_KNOWN_SINGLETON_TABLE_KEY: json.dumps(entry).encode()
        }
    }


def _ctx(**overrides):
    kwargs = {
        "view": 2,
        "seqno": 7,
        "node_certificates": {"node0": CERT},
        "check_signing_node": lambda node: None,
    }
    kwargs.update(overrides)
    return RootSignatureContext(**kwargs)


def test_registry_pins_current_verifiers():
    """Pins the shipped registry, so adding or removing a scheme is deliberate."""
    assert list(ROOT_SIGNATURE_VERIFIERS) == ["raw", "cose"]
    assert ROOT_SIGNATURE_VERIFIERS["raw"][0] == SIGNATURE_TX_TABLE_NAME
    assert ROOT_SIGNATURE_VERIFIERS["cose"][0] == COSE_SIGNATURE_TX_TABLE_NAME


def test_signature_tables_are_derived_from_the_registry():
    """``LedgerValidator`` only reaches the dispatcher for transactions that
    ``is_signature_transaction`` recognises, so a registered scheme's table must
    be recognised without a second edit."""
    assert SIGNATURE_TABLE_NAMES == frozenset(
        table for table, _ in ROOT_SIGNATURE_VERIFIERS.values()
    )
    for table, _ in ROOT_SIGNATURE_VERIFIERS.values():
        assert is_signature_transaction({table: {}})
    assert not is_signature_transaction({"public:ccf.gov.nodes.info": {}})


def test_nothing_is_verified_without_a_signature():
    """Neither a transaction without signature tables, nor one whose signature
    table carries no entry, counts as a signature."""
    empty = {SIGNATURE_TX_TABLE_NAME: {}, COSE_SIGNATURE_TX_TABLE_NAME: {}}

    assert verify_all_root_signatures({}, ROOT, _ctx()) == []
    assert verify_all_root_signatures(empty, ROOT, _ctx()) == []


def test_a_new_verifier_is_picked_up(monkeypatch):
    """A new scheme needs a verifier plus one registry entry, no call site change."""
    table = "public:ccf.internal.cose_pqc_signatures"
    monkeypatch.setitem(
        ROOT_SIGNATURE_VERIFIERS, "cose_pqc", (table, lambda tables, root, ctx: True)
    )

    assert verify_all_root_signatures({}, ROOT, _ctx()) == ["cose_pqc"]


def test_raw_accepts_a_valid_signature():
    assert verify_all_root_signatures(_raw_tx(cert=CERT), ROOT, _ctx()) == ["raw"]


def test_raw_rejects_a_tampered_signature():
    tables = _raw_tx()
    entry = json.loads(tables[SIGNATURE_TX_TABLE_NAME][WELL_KNOWN_SINGLETON_TABLE_KEY])
    sig = bytearray(base64.b64decode(entry["sig"]))
    sig[-1] ^= 0xFF
    entry["sig"] = base64.b64encode(bytes(sig)).decode()
    tables[SIGNATURE_TX_TABLE_NAME][WELL_KNOWN_SINGLETON_TABLE_KEY] = json.dumps(
        entry
    ).encode()

    with pytest.raises(InvalidRootSignatureException):
        verify_all_root_signatures(tables, ROOT, _ctx())


def test_raw_rejects_root_mismatch():
    """The signature is valid over the root the entry claims, but that is not
    the root computed from the ledger."""
    with pytest.raises(InvalidRootException):
        verify_all_root_signatures(_raw_tx(), b"\x6b" * 32, _ctx())


def test_raw_rejects_embedded_cert_for_a_different_key():
    """The entry embeds a certificate whose key differs from the one trusted
    for that node."""
    _, other_cert = _ec_identity()

    with pytest.raises(AssertionError, match="Mismatch in public key"):
        verify_all_root_signatures(_raw_tx(cert=other_cert), ROOT, _ctx())


def test_raw_rejects_untrustworthy_signer():
    """The signature must sit in its own transaction, and be issued by a known
    node that was entitled to sign."""

    def _reject(node):
        raise UntrustedNodeException(node)

    with pytest.raises(ValueError, match="does not match transaction header"):
        verify_all_root_signatures(_raw_tx(), ROOT, _ctx(seqno=8))

    with pytest.raises(KeyError):
        verify_all_root_signatures(_raw_tx(), ROOT, _ctx(node_certificates={}))

    with pytest.raises(UntrustedNodeException, match="node0"):
        verify_all_root_signatures(_raw_tx(), ROOT, _ctx(check_signing_node=_reject))


def test_cose_requires_a_service_cert():
    tables = {
        COSE_SIGNATURE_TX_TABLE_NAME: {
            WELL_KNOWN_SINGLETON_TABLE_KEY: json.dumps(
                base64.b64encode(b"cose-bytes").decode()
            ).encode()
        }
    }

    with pytest.raises(AssertionError, match="service certificate"):
        verify_all_root_signatures(tables, ROOT, _ctx())
