# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import base64
import functools
import json
from dataclasses import dataclass
from typing import Any, Container, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509 import load_pem_x509_certificate

import ccf.cose
from ccf.merkletree import MerkleTree

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


SIGNATURE_TX_TABLE_NAME: str = "public:ccf.internal.signatures"
"""KV table carrying the raw ECDSA signature over the Merkle root."""

COSE_SIGNATURE_TX_TABLE_NAME: str = "public:ccf.internal.cose_signatures"
"""KV table carrying the COSE Sign1 signature over the Merkle root."""

SIGNATURE_TABLE_NAMES: frozenset[str] = frozenset(
    {SIGNATURE_TX_TABLE_NAME, COSE_SIGNATURE_TX_TABLE_NAME}
)
"""All KV table names that carry a ledger-transaction signature."""

WELL_KNOWN_SINGLETON_TABLE_KEY: bytes = bytes(bytearray(8))
"""Key used by CCF to record entries in single-row KV tables."""


def is_signature_transaction(tx_tables: Container[str]) -> bool:
    """Return ``True`` if ``tx_tables`` contains any signature table.

    ``tx_tables`` is any object supporting ``in`` over table names. Typical
    callers pass the dict returned by
    ``transaction.get_public_domain().get_tables()``.
    """
    return any(name in tx_tables for name in SIGNATURE_TABLE_NAMES)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class InvalidRootException(Exception):
    """MerkleTree root doesn't match with the root reported in the signature's table"""


class InvalidRootSignatureException(Exception):
    """Signature of the MerkleRoot doesn't match with the signature that's reported in the signature's table"""


class InvalidRootCoseSignatureException(Exception):
    """COSE signature of the MerkleRoot doesn't pass COSE verification"""


class UntrustedNodeException(Exception):
    """The signing node wasn't part of the network when it issued a signature."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=64)
def spki_from_cert(cert: bytes) -> bytes:
    """Return the DER-encoded SubjectPublicKeyInfo for a PEM certificate."""
    cert_obj = load_pem_x509_certificate(cert)
    return cert_obj.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# ---------------------------------------------------------------------------
# Parsers: pure tx -> structured data, no validator state
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RawSignaturePayload:
    """A single raw-signature entry parsed from a signature transaction.

    Every field is derived from the per-tx contents of
    :data:`SIGNATURE_TX_TABLE_NAME`; nothing here depends on validator state.
    """

    seqno: int
    view: int
    signing_node: str
    root: bytes
    signature: bytes
    embedded_cert: Optional[bytes]
    """PEM bytes of the signing node's certificate as embedded in the
    signature entry (``"cert"`` field), or ``None`` if absent."""


def parse_raw_signature_from_tx(
    tx_tables: Mapping[str, Any],
) -> Optional[RawSignaturePayload]:
    """Return the raw signature payload in this tx, or ``None`` if absent.

    The signature table is a singleton (one entry per tx, keyed by
    :data:`WELL_KNOWN_SINGLETON_TABLE_KEY`), so at most one payload exists.
    """
    signature_table = tx_tables.get(SIGNATURE_TX_TABLE_NAME)
    if signature_table is None:
        return None

    encoded = signature_table.get(WELL_KNOWN_SINGLETON_TABLE_KEY)
    if encoded is None:
        return None

    sig = json.loads(encoded)
    embedded_cert = sig["cert"].encode("utf-8") if "cert" in sig else None
    return RawSignaturePayload(
        seqno=sig["seqno"],
        view=sig["view"],
        signing_node=sig["node"],
        root=bytes.fromhex(sig["root"]),
        signature=base64.b64decode(sig["sig"]),
        embedded_cert=embedded_cert,
    )


def parse_cose_signature_from_tx(tx_tables: Mapping[str, Any]) -> Optional[bytes]:
    """Return the COSE Sign1 bytes from this tx, or ``None`` if absent.

    Strips the JSON-string + base64 wrapper used in the KV table and returns
    the decoded COSE Sign1 bytes ready for :func:`verify_cose_root_signature`.
    """
    cose_table = tx_tables.get(COSE_SIGNATURE_TX_TABLE_NAME)
    if cose_table is None:
        return None
    encoded = cose_table.get(WELL_KNOWN_SINGLETON_TABLE_KEY)
    if encoded is None:
        return None
    return base64.b64decode(json.loads(encoded))


# ---------------------------------------------------------------------------
# Primitive verifiers: pure crypto / comparison, take direct inputs
# ---------------------------------------------------------------------------


def verify_raw_root_signature(node_cert: bytes, root: bytes, signature: bytes) -> None:
    """Verify a raw ECDSA signature over a (prehashed) Merkle root.

    Raises :class:`InvalidRootSignatureException` if verification fails.
    """
    try:
        cert = load_pem_x509_certificate(node_cert)
        pub_key = cert.public_key()

        assert isinstance(pub_key, ec.EllipticCurvePublicKey)
        pub_key.verify(
            signature,
            root,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
    except InvalidSignature as exc:
        raise InvalidRootSignatureException(
            "Signature verification failed:"
            + f"\nCertificate: {node_cert.decode()}"
            + f"\nSignature: {base64.b64encode(signature).decode()}"
            + f"\nRoot: {root.hex()}"
        ) from exc


def verify_cose_root_signature(
    service_cert: str, root: bytes, cose_sign1: bytes
) -> None:
    """Verify a COSE Sign1 signature over a Merkle root against the service cert.

    Raises :class:`InvalidRootCoseSignatureException` if verification fails.
    """
    try:
        ccf.cose.verify_cose_sign1_with_cert(
            certificate=service_cert.encode("ascii"),
            cose_sign1=cose_sign1,
            use_key=True,
            payload=root,
        )
    except Exception as exc:
        raise InvalidRootCoseSignatureException(
            "Signature verification failed:"
            + f"\nCertificate: {service_cert}"
            + f"\nRoot: {root!r}"
        ) from exc


def verify_merkle_root(merkle_tree: MerkleTree, existing_root: bytes) -> None:
    """Raise :class:`InvalidRootException` if the tree's root differs from ``existing_root``."""
    root = merkle_tree.get_merkle_root()
    if root != existing_root:
        raise InvalidRootException(
            f"\nComputed root: {root.hex()} \nExisting root from ledger: {existing_root.hex()}"
        )
