# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Root-signature parsing and verification for CCF ledgers.

Each signature scheme is one verifier in :data:`ROOT_SIGNATURE_VERIFIERS`,
dispatched by :func:`verify_all_root_signatures`. Adding a scheme is a verifier
plus one registry entry; a scheme signed by a new identity adds a field to
:class:`RootSignatureContext`.
"""

import base64
import functools
import json
from collections.abc import Callable, Container, Mapping
from dataclasses import dataclass
from typing import Any

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

WELL_KNOWN_SINGLETON_TABLE_KEY: bytes = bytes(bytearray(8))
"""Key used by CCF to record entries in single-row KV tables."""


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
    embedded_cert: bytes | None
    """PEM bytes of the signing node's certificate as embedded in the
    signature entry (``"cert"`` field), or ``None`` if absent."""


def parse_raw_signature_from_tx(
    tx_tables: Mapping[str, Any],
) -> RawSignaturePayload | None:
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


def parse_cose_signature_from_tx(tx_tables: Mapping[str, Any]) -> bytes | None:
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


def verify_cose_root_signature_with_key(
    service_key_pem: bytes, root: bytes, cose_sign1: bytes
):
    """Verify a COSE Sign1 signature over a Merkle root against the service key.

    The key-taking counterpart of :func:`verify_cose_root_signature`, for callers
    holding the service public key rather than its certificate. Returns the
    decoded protected headers, and raises
    :class:`InvalidRootCoseSignatureException` if verification fails.
    """
    try:
        return ccf.cose.verify_cose_sign1_with_key(
            service_key_pem, cose_sign1, payload=root
        )
    except Exception as exc:
        raise InvalidRootCoseSignatureException(
            "Signature verification failed:"
            + f"\nKey: {service_key_pem.decode()}"
            + f"\nRoot: {root!r}"
        ) from exc


def verify_root(computed_root: bytes, existing_root: bytes) -> None:
    """Raise :class:`InvalidRootException` if the two roots differ."""
    if computed_root != existing_root:
        raise InvalidRootException(
            f"\nComputed root: {computed_root.hex()} \nExisting root from ledger: {existing_root.hex()}"
        )


def verify_merkle_root(merkle_tree: MerkleTree, existing_root: bytes) -> None:
    """Raise :class:`InvalidRootException` if the tree's root differs from ``existing_root``."""
    verify_root(merkle_tree.get_merkle_root(), existing_root)


# ---------------------------------------------------------------------------
# Root signature verifiers: one per scheme
# ---------------------------------------------------------------------------


@dataclass
class RootSignatureContext:
    """The signing identities a verifier may need, beyond the transaction and
    the Merkle root computed for it."""

    view: int
    seqno: int

    service_cert_pem: str | None = None
    """PEM service certificate, the identity behind COSE signatures."""

    node_certificates: Mapping[str, bytes] | None = None
    """PEM certificates of known nodes by node id. Raw signatures are issued by
    whichever node was primary, so they are verified against these."""

    check_signing_node: Callable[[str], None] | None = None
    """Must raise if the given node was not entitled to sign at this point in
    the ledger."""


def verify_raw_root(
    tx_tables: Mapping[str, Any], computed_root: bytes, ctx: RootSignatureContext
) -> bool:
    """Verify the raw ECDSA root signature, if this transaction carries one."""
    payload = parse_raw_signature_from_tx(tx_tables)
    if payload is None:
        return False

    assert ctx.node_certificates is not None
    assert ctx.check_signing_node is not None

    if payload.view != ctx.view or payload.seqno != ctx.seqno:
        raise ValueError(
            f"Signature payload position {payload.view}.{payload.seqno} does not "
            f"match transaction header position {ctx.view}.{ctx.seqno}"
        )
    ctx.check_signing_node(payload.signing_node)
    cert = ctx.node_certificates[payload.signing_node]
    if payload.embedded_cert is not None:
        assert spki_from_cert(cert) == spki_from_cert(
            payload.embedded_cert
        ), f"Mismatch in public key for node {payload.signing_node}"
    verify_raw_root_signature(cert, payload.root, payload.signature)
    verify_root(computed_root, payload.root)
    return True


def verify_cose_root(
    tx_tables: Mapping[str, Any], computed_root: bytes, ctx: RootSignatureContext
) -> bool:
    """Verify the COSE Sign1 root signature, if this transaction carries one."""
    cose_sign1 = parse_cose_signature_from_tx(tx_tables)
    if cose_sign1 is None:
        return False

    assert (
        ctx.service_cert_pem is not None
    ), "Cannot verify COSE root signature without a known service certificate"
    verify_cose_root_signature(ctx.service_cert_pem, computed_root, cose_sign1)
    return True


ROOT_SIGNATURE_VERIFIERS: dict[
    str, tuple[str, Callable[[Mapping[str, Any], bytes, RootSignatureContext], bool]]
] = {
    "raw": (SIGNATURE_TX_TABLE_NAME, verify_raw_root),
    "cose": (COSE_SIGNATURE_TX_TABLE_NAME, verify_cose_root),
}
"""Every root signature scheme CCF may write, as ``name -> (KV table, verifier)``,
in verification order. :data:`SIGNATURE_TABLE_NAMES` is derived from the tables
here, so a new scheme is recognised as a signature transaction automatically."""

SIGNATURE_TABLE_NAMES: frozenset[str] = frozenset(
    table for table, _ in ROOT_SIGNATURE_VERIFIERS.values()
)
"""All KV table names that carry a ledger-transaction signature."""


def is_signature_transaction(tx_tables: Container[str]) -> bool:
    """Return ``True`` if ``tx_tables`` contains any signature table.

    ``tx_tables`` is any object supporting ``in`` over table names. Typical
    callers pass the dict returned by
    ``transaction.get_public_domain().get_tables()``.
    """
    return any(name in tx_tables for name in SIGNATURE_TABLE_NAMES)


def verify_all_root_signatures(
    tx_tables: Mapping[str, Any], computed_root: bytes, ctx: RootSignatureContext
) -> list[str]:
    """Run every verifier, and return the names of those that found a signature.

    An empty result means the transaction carried no root signature at all;
    callers decide whether that is acceptable.
    """
    return [
        name
        for name, (_, verify) in ROOT_SIGNATURE_VERIFIERS.items()
        if verify(tx_tables, computed_root, ctx)
    ]
