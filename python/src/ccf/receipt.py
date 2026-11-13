# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import base64
from collections.abc import Mapping, Sequence
from hashlib import sha256
from io import BytesIO
from math import isnan
from typing import Any, cast

import cwt
import cwt.const
from cbor2 import CBORDecodeError, CBORDecoder, CBORTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)
from cryptography.x509 import Certificate
from cryptography.x509.verification import PolicyBuilder, Store

import ccf.signatures
from ccf.cose import (
    CCF_CONSISTENCY_PROOF_ANCHOR_LABEL,
    CCF_CONSISTENCY_PROOF_PATH_LABEL,
    CCF_MAX_COMMIT_EVIDENCE_SIZE,
    CCF_PROOF_LEAF_LABEL,
    CCF_PROOF_PATH_LABEL,
    COSE_PHDR_VDP_LABEL,
    COSE_PHDR_VDS_CCF_LEDGER_SHA256,
    COSE_PHDR_VDS_LABEL,
    COSE_RECEIPT_CONSISTENCY_PROOF_LABEL,
    COSE_RECEIPT_INCLUSION_PROOF_LABEL,
    key_fingerprint_from_key,
    verify_cose_sign1_with_key,
)
from ccf.tx_id import TxID

_MAX_RECEIPT_CBOR_DEPTH = 400

# Tags that cbor2 6 converts to Python values by default. Receipt decoding
# keeps them as CBORTag, so that, for example, a bignum cannot stand in for an
# integer label or a self-described CBOR tag for a plain map.
_CBOR2_SEMANTIC_TAGS = (
    *range(6),
    25,
    28,
    29,
    30,
    35,
    36,
    37,
    52,
    54,
    100,
    256,
    258,
    260,
    261,
    1004,
    43000,
    55799,
)
# cbor2 decodes the contents of other tags as immutable containers. Decoding
# COSE_Sign1 like the tags above keeps its contents as a mutable array and map.
_COSE_SIGN1_TAG = cwt.const.COSE_TYPE_TO_TAG[cwt.COSETypes.SIGN1]


def _keep_tag(tag: int):
    def decode(value: Any, _immutable: bool) -> CBORTag:
        return CBORTag(tag, value)

    return decode


_KEEP_TAGS = {tag: _keep_tag(tag) for tag in (*_CBOR2_SEMANTIC_TAGS, _COSE_SIGN1_TAG)}


def _contains_nan(value: Any) -> bool:
    """Return whether value is, or contains, a NaN."""
    if type(value) is float:
        return isnan(value)
    if type(value) is tuple:
        return any(_contains_nan(item) for item in cast(tuple[Any, ...], value))
    if isinstance(value, Mapping):
        items = cast(Mapping[Any, Any], value).items()
        return any(_contains_nan(k) or _contains_nan(v) for k, v in items)
    if type(value) is CBORTag:
        return _contains_nan(value.value)
    return False


def _reject_nan_keys(value: Mapping[Any, Any], _immutable: bool) -> Mapping[Any, Any]:
    """Reject NaN map keys, which cbor2 does not compare as RFC 8949 requires.

    NaNs never compare equal in Python, and cbor2 quiets signaling NaNs when
    widening half and single precision floats, so the encoded significands
    needed to detect duplicate NaN keys are unavailable.
    """
    if any(_contains_nan(key) for key in value):
        raise ValueError("NaN map key")
    return value


def _decode_receipt_cbor(encoded: bytes) -> Any:
    """Strictly decode a single complete CBOR item from encoded."""
    if type(encoded) is not bytes:
        raise ValueError("Encoded receipt data must be bstr")
    stream = BytesIO(encoded)
    try:
        result = CBORDecoder(
            stream,
            object_hook=_reject_nan_keys,
            semantic_decoders=_KEEP_TAGS,
            max_depth=_MAX_RECEIPT_CBOR_DEPTH,
            allow_duplicate_keys=False,
        ).decode()
    except CBORDecodeError as exc:
        cause = f" ({exc.__cause__})" if exc.__cause__ else ""
        raise ValueError(f"Invalid receipt CBOR: {exc}{cause}") from exc
    if stream.read(1):
        raise ValueError("Trailing data after receipt CBOR")
    return result


# Each element is [left, sibling digest], where left is True if the sibling
# is on the left.
_ProofPath = list[list[Any]]


def _require_map(
    value: Any, name: str, keys: set[int] | None = None
) -> dict[int | str, Any]:
    """Return value if it is a map with integer or text labels, optionally
    exactly matching keys."""
    if type(value) is not dict:
        raise ValueError(f"{name} must be a map")
    result = cast(dict[int | str, Any], value)
    if any(type(label) not in (int, str) for label in result):
        raise ValueError(f"{name} labels must be integers or text strings")
    if keys is not None and result.keys() != keys:
        raise ValueError(f"{name} must contain exactly labels {sorted(keys)}")
    return result


def _require_digest(value: Any) -> None:
    """Raise unless value is a 32-byte bstr."""
    if type(value) is not bytes or len(value) != 32:
        raise ValueError("Digest must be a 32-byte bstr")


def _proof_path(value: Any, *, consistency: bool = False) -> _ProofPath:
    """Return value if it is a valid inclusion or consistency proof path."""
    if type(value) is not list:
        raise ValueError("Proof path must be an array")
    path = cast(_ProofPath, value)
    if consistency and not path:
        raise ValueError("Consistency proof path must not be empty")
    for element in path:
        if (
            type(element) is not list
            or len(element) != 2
            or type(element[0]) is not bool
        ):
            raise ValueError("Proof path elements must be [bool, bstr32]")
        _require_digest(element[1])
    if consistency and path[0][0]:
        raise ValueError("First consistency proof sibling must be on the right")
    return path


def _fold_path(accumulator: bytes, path: _ProofPath) -> bytes:
    """Hash accumulator with each sibling in path, returning the root."""
    for left, digest in path:
        accumulator = sha256(
            digest + accumulator if left else accumulator + digest
        ).digest()
    return accumulator


def root(leaf: str, proof: list[dict[str, str]]) -> str:
    """
    Recompute root of Merkle tree from a leaf and a proof of the form:
    [{"left": digest}, {"right": digest}, ...]
    """
    current = bytes.fromhex(leaf)
    for n in proof:
        if "left" in n:
            current = sha256(bytes.fromhex(n["left"]) + current).digest()
        else:
            current = sha256(current + bytes.fromhex(n["right"])).digest()
    return current.hex()


def verify(root: str, signature: str, cert: Certificate):
    """
    Verify signature over root of Merkle Tree
    """
    sig = base64.b64decode(signature)
    pk = cert.public_key()
    assert isinstance(pk, ec.EllipticCurvePublicKey)
    pk.verify(
        sig,
        bytes.fromhex(root),
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )


def check_endorsement(endorsee: Certificate, endorser: Certificate):
    """
    Check endorser has endorsed endorsee
    """
    digest_algo = endorsee.signature_hash_algorithm
    assert digest_algo
    digester = hashes.Hash(digest_algo)
    digester.update(endorsee.tbs_certificate_bytes)
    digest = digester.finalize()
    endorser_pk = endorser.public_key()
    assert isinstance(endorser_pk, ec.EllipticCurvePublicKey)
    endorser_pk.verify(
        endorsee.signature, digest, ec.ECDSA(utils.Prehashed(digest_algo))
    )


def check_endorsements(
    node_cert: Certificate,
    service_cert: Certificate,
    endorsements: list[Certificate],
):
    """
    Check a node certificate is endorsed by a service certificate, transitively through a list of endorsements.
    """
    cert_i = node_cert
    for endorsement in endorsements:
        check_endorsement(cert_i, endorsement)
        cert_i = endorsement
    check_endorsement(cert_i, service_cert)


def check_cert_chain(
    node_cert: Certificate,
    service_cert: Certificate,
    endorsements: list[Certificate],
):
    """
    Use default cryptography policy to verify CCF cert chain
    """
    builder = PolicyBuilder()
    builder = builder.store(Store([service_cert]))

    # This would ideally be `build_server_verifier`, but that requires a
    # Subject which is either a valid DNSName or IPAddress. Our node cert's
    # Subject is "CCF Node", and we may not have a better value in SAN
    verifier = builder.build_client_verifier()
    verifier.verify(leaf=node_cert, intermediates=endorsements)


# A recovered service starts its first view this many views after the last view
# of the previous service, as aft::starting_view_change in the node
_RECOVERY_VIEW_INCREMENT = 2


def _require_endorsements_sequence(endorsements: Sequence[bytes]) -> None:
    """Raise TypeError if endorsements is a single message rather than a
    sequence of COSE_Sign1 messages."""
    if type(endorsements) in (bytes, bytearray, memoryview, str):
        raise TypeError(
            "Endorsements must be a sequence of COSE Sign1 messages, not a single "
            f"{type(endorsements).__name__}"
        )


def _txid_claim(claims: Mapping[Any, Any], label: str) -> TxID:
    """Return the valid transaction ID at label in a ccf.v1 claims map."""
    value = claims.get(label)
    view, seqno = TxID.parse(value if type(value) is str else None)
    if view is None or seqno is None:
        raise ValueError(f"{label} must be a valid transaction ID")
    return TxID(view, seqno)


def verify_cose_endorsements(
    endorsements: Sequence[bytes], key: CertificatePublicKeyTypes
) -> tuple[CertificatePublicKeyTypes, TxID, TxID]:
    """
    Verify a chain of COSE service identity endorsements from a trusted service
    key, and return the service key it endorses last, with the first and last
    transaction IDs of the epoch that key signed.

    The chain is a sequence of COSE_Sign1 messages, ordered newest first, as
    served for a receipt of a transaction signed by a previous service
    identity. The first endorsement must be signed by key, and each later one
    by the key that the one before it endorses. Each epoch must end, as a
    disaster recovery leaves it, one sequence number and two views before the
    start of the epoch of the endorsement before it.
    Keys are EC keys for CLASSICAL service identities, and ML-DSA keys for PQ
    ones.
    """
    _require_endorsements_sequence(endorsements)
    if not endorsements:
        raise ValueError("Endorsements chain must not be empty")

    endorsed_key = key
    newer_begin: TxID | None = None
    begin = end = TxID(None, None)
    for index, endorsement in enumerate(endorsements):
        endorsing_key_pem = endorsed_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
        try:
            phdr, _, payload = verify_cose_sign1_with_key(
                endorsing_key_pem, endorsement
            )
        except Exception as exc:
            raise ValueError(
                f"Endorsement {index} is not signed by the key it must be signed by"
            ) from exc
        claims = phdr.get("ccf.v1")
        if type(claims) is not dict:
            raise ValueError("Endorsement must have ccf.v1 claims")
        claims = cast(dict[Any, Any], claims)
        begin = _txid_claim(claims, "epoch.start.txid")
        end = _txid_claim(claims, "epoch.end.txid")
        assert begin.seqno is not None and end.seqno is not None
        if end.seqno < begin.seqno:
            raise ValueError(f"Endorsement epoch {begin} - {end} is empty")
        if newer_begin is not None:
            assert newer_begin.seqno is not None and newer_begin.view is not None
            assert end.view is not None
            if (
                end.seqno + 1 != newer_begin.seqno
                or end.view + _RECOVERY_VIEW_INCREMENT != newer_begin.view
            ):
                raise ValueError(
                    f"Endorsement epoch {begin} - {end} does not end just "
                    f"before the next epoch, which starts at {newer_begin}"
                )
        newer_begin = begin
        endorsed_key = cast(CertificatePublicKeyTypes, load_der_public_key(payload))

    return endorsed_key, begin, end


def verify_cose(
    receipt_bytes: bytes,
    key: CertificatePublicKeyTypes,
    claim_digest: bytes,
    endorsements: Sequence[bytes] = (),
):
    """
    Verify a COSE Sign1 receipt as defined in https://www.rfc-editor.org/rfc/rfc9942.html,
    using the CCF tree algorithm defined in https://datatracker.ietf.org/doc/draft-ietf-scitt-receipts-ccf-profile/.

    The receipt must have a detached payload and prove inclusion of the caller's
    claims digest against the supplied service key.
    Any accompanying consistency proofs must reconstruct the same signed root;
    this does not establish trust in their older roots.

    The service key is an EC key for a CLASSICAL receipt, or an ML-DSA key for
    a PQ receipt, which requires cryptography 48 or later.
    For a receipt signed by a previous service identity, endorsements is the
    COSE endorsements chain of the receipt, newest first, and key is the
    trusted current service key. The receipt must then be signed by the key
    that the chain endorses last, for a transaction in the epoch of that key
    (see :func:`verify_cose_endorsements`).
    """
    _require_digest(claim_digest)
    _require_endorsements_sequence(endorsements)
    signing_key = key
    epoch: tuple[TxID, TxID] | None = None
    if endorsements:
        signing_key, begin, end = verify_cose_endorsements(endorsements, key)
        epoch = (begin, end)
    key_pem = signing_key.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    expected_kid = key_fingerprint_from_key(key_pem)

    receipt = _decode_receipt_cbor(receipt_bytes)
    if (
        type(receipt) is not CBORTag
        or receipt.tag != cwt.const.COSE_TYPE_TO_TAG[cwt.COSETypes.SIGN1]
    ):
        raise ValueError("Receipt must be a tagged four-element COSE Sign1 message")
    receipt_value = cast(list[Any], receipt.value)
    if type(receipt_value) is not list or len(receipt_value) != 4:
        raise ValueError("Receipt must be a tagged four-element COSE Sign1 message")
    phdr_bytes, uhdr, payload, signature = receipt_value
    phdr = _require_map(_decode_receipt_cbor(phdr_bytes), "Protected header")
    uhdr = _require_map(uhdr, "Unprotected header")
    if payload is not None:
        raise ValueError("Receipt payload must be detached (nil)")
    if type(signature) is not bytes:
        raise ValueError("Receipt signature must be bstr")
    if type(phdr.get(int(cwt.COSEHeaders.ALG))) is not int:
        raise ValueError("Protected alg must be an integer")

    kid = phdr.get(int(cwt.COSEHeaders.KID))
    if type(kid) is not bytes or kid != expected_kid.encode("ascii"):
        raise ValueError(f"Receipt is not signed by the expected key {expected_kid}")

    if epoch is not None:
        claims = phdr.get("ccf.v1")
        if type(claims) is not dict:
            raise ValueError("Receipt must have ccf.v1 claims")
        txid = _txid_claim(cast(dict[Any, Any], claims), "txid")
        begin, end = epoch
        assert txid.seqno is not None
        assert begin.seqno is not None and end.seqno is not None
        if not begin.seqno <= txid.seqno <= end.seqno:
            raise ValueError(
                f"Receipt for {txid} is not in the epoch {begin} - {end} of the "
                "endorsed key"
            )

    if COSE_PHDR_VDS_LABEL not in phdr:
        raise ValueError("Verifiable data structure type is required")
    if (
        type(phdr[COSE_PHDR_VDS_LABEL]) is not int
        or phdr[COSE_PHDR_VDS_LABEL] != COSE_PHDR_VDS_CCF_LEDGER_SHA256
    ):
        raise ValueError("vds(395) protected header must be CCF_LEDGER_SHA256(2)")

    if COSE_PHDR_VDP_LABEL not in uhdr:
        raise ValueError("Verifiable data proof is required")
    proofs = _require_map(uhdr[COSE_PHDR_VDP_LABEL], "Verifiable data proof")
    if not proofs or not proofs.keys() <= {
        COSE_RECEIPT_INCLUSION_PROOF_LABEL,
        COSE_RECEIPT_CONSISTENCY_PROOF_LABEL,
    }:
        raise ValueError("Verifiable data proof contains invalid labels")
    for proof_list in proofs.values():
        if (
            type(proof_list) is not list
            or not proof_list
            or any(type(proof) is not bytes for proof in cast(list[Any], proof_list))
        ):
            raise ValueError("Proofs must be non-empty arrays of bstr")
    if COSE_RECEIPT_INCLUSION_PROOF_LABEL not in proofs:
        raise ValueError("Inclusion proof is required")

    signed_root: bytes | None = None
    for inclusion_proof in proofs[COSE_RECEIPT_INCLUSION_PROOF_LABEL]:
        proof = _require_map(
            _decode_receipt_cbor(inclusion_proof),
            "Inclusion proof",
            {CCF_PROOF_LEAF_LABEL, CCF_PROOF_PATH_LABEL},
        )
        leaf = cast(list[Any], proof[CCF_PROOF_LEAF_LABEL])
        if type(leaf) is not list or len(leaf) != 3:
            raise ValueError("Leaf must be a three-element array")
        _require_digest(leaf[0])
        _require_digest(leaf[2])
        if (
            type(leaf[1]) is not str
            or not 1 <= len(leaf[1].encode("utf-8")) <= CCF_MAX_COMMIT_EVIDENCE_SIZE
        ):
            raise ValueError(
                "Commit evidence must be a tstr of "
                f"1..{CCF_MAX_COMMIT_EVIDENCE_SIZE} UTF-8 bytes"
            )
        if claim_digest != leaf[2]:
            raise ValueError(f"Claim digest mismatch: {leaf[2]!r} != {claim_digest!r}")
        accumulator = sha256(
            leaf[0] + sha256(leaf[1].encode()).digest() + leaf[2]
        ).digest()
        accumulator = _fold_path(accumulator, _proof_path(proof[CCF_PROOF_PATH_LABEL]))
        if signed_root is not None and accumulator != signed_root:
            raise ValueError("Inclusion proofs reconstruct different roots")
        signed_root = accumulator

    for consistency_proof in proofs.get(COSE_RECEIPT_CONSISTENCY_PROOF_LABEL, []):
        proof = _require_map(
            _decode_receipt_cbor(consistency_proof),
            "Consistency proof",
            {CCF_CONSISTENCY_PROOF_ANCHOR_LABEL, CCF_CONSISTENCY_PROOF_PATH_LABEL},
        )
        anchor = proof[CCF_CONSISTENCY_PROOF_ANCHOR_LABEL]
        _require_digest(anchor)
        path = _proof_path(proof[CCF_CONSISTENCY_PROOF_PATH_LABEL], consistency=True)
        if _fold_path(anchor, path) != signed_root:
            raise ValueError("Consistency proof does not reconstruct the signed root")

    # The inclusion proofs array is non-empty, so signed_root has been set.
    assert signed_root is not None
    ic_phdr, _, _ = ccf.signatures.verify_cose_root_signature_with_key(
        key_pem.encode("ascii"), signed_root, receipt_bytes
    )
    return ic_phdr
