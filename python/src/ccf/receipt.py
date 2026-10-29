# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import base64
from collections.abc import Mapping
from hashlib import sha256
from io import BytesIO
from math import isnan
from typing import Any

import cwt
import cwt.const
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import Certificate
from cryptography.x509.base import CertificatePublicKeyTypes
from cryptography.x509.verification import PolicyBuilder, Store

import ccf.signatures
from ccf.cose import (
    CCF_PROOF_LEAF_LABEL,
    CCF_PROOF_PATH_LABEL,
    COSE_PHDR_VDP_LABEL,
    COSE_PHDR_VDS_CCF_LEDGER_SHA256,
    COSE_PHDR_VDS_LABEL,
    COSE_RECEIPT_CONSISTENCY_PROOF_LABEL,
    COSE_RECEIPT_INCLUSION_PROOF_LABEL,
    key_fingerprint_from_key,
)

# isort: split
# Temporary cbor2 5.x workaround for strict "no duplicate keys" decoding.
# python-cwt currently requires cbor2 < 6; once it supports cbor2 >= 6.1,
# replace this shim with the public allow_duplicate_keys=False option,
# retaining tag/type preservation and complete-input checks. Keep the private
# imports here to make the workaround's dependency on cbor2 internals explicit.
from cbor2._decoder import CBORDecoder, major_decoders
from cbor2._types import CBORDecodeError, CBORTag, FrozenDict, break_marker


class _ReceiptDecoder(CBORDecoder):
    """Keep CBOR types and reject duplicate keys before a map loses them.

    cbor2 5.x's object_hook runs after duplicates have been overwritten.
    Reuse its primitive decoders but handle maps and preserve tags rather
    than applying semantic conversions.
    """

    def __init__(self, stream: BytesIO):
        super().__init__(stream)
        self._receipt_depth = 0
        self._allow_break = False
        self._nan_keys: dict[int, float] = {}

    def decode(self, immutable: bool = False, unshared: bool = False) -> Any:
        position = self.fp.tell()
        initial = self.read(1)
        self.fp.seek(position)
        if initial == b"\xff" and not self._allow_break:
            raise ValueError("Unexpected CBOR break")
        if initial == b"\xf8":
            value = self.fp.read(2)
            self.fp.seek(position)
            if len(value) == 2 and value[1] < 32:
                raise ValueError("Invalid two-byte CBOR simple value")
        if self._receipt_depth >= 400:
            raise ValueError("Receipt CBOR nesting is too deep")
        self._receipt_depth += 1
        previous_allow_break = self._allow_break
        previous_immutable = self._immutable
        previous_share_index = self._share_index
        if immutable:
            self._immutable = True
        if unshared:
            self._share_index = None
        self._allow_break = initial == b"\x9f"
        try:
            if initial and initial[0] >> 5 == 5:
                self.read(1)
                return self._decode_map(initial[0] & 31)
            if initial and initial[0] >> 5 == 6:
                self.read(1)
                tag = self._decode_length(initial[0] & 31)
                return CBORTag(tag, self.decode())
            self.read(1)

            if self._immutable and initial[0] in (0xF9, 0xFA, 0xFB):
                position = self.fp.tell()
                subtype = initial[0] & 31
                encoded = self.read(1 << (subtype - 24))
                self.fp.seek(position)
                value = major_decoders[7](self, subtype)
                if isnan(value):
                    # RFC 8949 compares NaN key significands, not Python's
                    # always-false NaN equality. Intern equivalent keys,
                    # including NaNs inside immutable container keys.
                    fraction_bits = {25: 10, 26: 23, 27: 52}[subtype]
                    significand = int.from_bytes(encoded, "big") & (
                        (1 << fraction_bits) - 1
                    )
                    return self._nan_keys.setdefault(
                        significand << (64 - fraction_bits), value
                    )
                return value

            return major_decoders[initial[0] >> 5](self, initial[0] & 31)
        finally:
            self._allow_break = previous_allow_break
            self._immutable = previous_immutable
            if unshared:
                self._share_index = previous_share_index
            self._receipt_depth -= 1

    def _decode(self, immutable: bool = False, unshared: bool = False) -> Any:
        # Older cbor2 5.x primitive decoders recurse through _decode instead
        # of decode. Both paths must apply the receipt-specific checks.
        return self.decode(immutable=immutable, unshared=unshared)

    def _decode_map(self, subtype: int) -> Mapping:
        length = self._decode_length(subtype, allow_indefinite=True)
        result: dict[Any, Any] = {}
        remaining = length
        while remaining is None or remaining > 0:
            self._allow_break = length is None
            key = self.decode(immutable=True, unshared=True)
            if key is break_marker:
                break
            self._allow_break = False
            try:
                if key in result:
                    raise ValueError("Duplicate CBOR map key")
                result[key] = self.decode(unshared=True)
            except TypeError as exc:
                raise ValueError("Invalid CBOR map key") from exc
            if remaining is not None:
                remaining -= 1
        return FrozenDict(result) if self._immutable else result


def _decode_receipt_cbor(encoded: bytes) -> Any:
    if type(encoded) is not bytes:
        raise ValueError("Encoded receipt data must be bstr")
    stream = BytesIO(encoded)
    try:
        result = _ReceiptDecoder(stream).decode()
    except (CBORDecodeError, TypeError, RecursionError) as exc:
        raise ValueError("Invalid receipt CBOR") from exc
    if stream.read(1):
        raise ValueError("Trailing data after receipt CBOR")
    return result


def _require_map(value: Any, name: str, keys: set[int] | None = None) -> dict:
    if type(value) is not dict:
        raise ValueError(f"{name} must be a map")
    if any(type(label) not in (int, str) for label in value):
        raise ValueError(f"{name} labels must be integers or text strings")
    if keys is not None and value.keys() != keys:
        raise ValueError(f"{name} must contain exactly labels {sorted(keys)}")
    return value


def _require_digest(value: Any) -> None:
    if type(value) is not bytes or len(value) != 32:
        raise ValueError("Digest must be a 32-byte bstr")


def _proof_path(value: Any, *, consistency: bool = False) -> list:
    if type(value) is not list:
        raise ValueError("Proof path must be an array")
    if consistency and not value:
        raise ValueError("Consistency proof path must not be empty")
    for element in value:
        if (
            type(element) is not list
            or len(element) != 2
            or type(element[0]) is not bool
        ):
            raise ValueError("Proof path elements must be [bool, bstr32]")
        _require_digest(element[1])
    if consistency and value[0][0]:
        raise ValueError("First consistency proof sibling must be on the right")
    return value


def _fold_path(accumulator: bytes, path: list) -> bytes:
    for left, digest in path:
        accumulator = sha256(
            digest + accumulator if left else accumulator + digest
        ).digest()
    return accumulator


def root(leaf: str, proof: list[dict]):
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


def verify_cose(
    receipt_bytes: bytes, key: CertificatePublicKeyTypes, claim_digest: bytes
):
    """
    Verify a COSE Sign1 receipt as defined in https://www.rfc-editor.org/rfc/rfc9942.html,
    using the CCF tree algorithm defined in https://datatracker.ietf.org/doc/draft-ietf-scitt-receipts-ccf-profile/.

    The receipt must have a detached payload and prove inclusion of the caller's
    claims digest against the supplied service key.
    Any accompanying consistency proofs must reconstruct the same signed root;
    this does not establish trust in their older roots.
    """
    _require_digest(claim_digest)
    key_pem = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(
        "ascii"
    )
    expected_kid = key_fingerprint_from_key(key_pem)

    receipt = _decode_receipt_cbor(receipt_bytes)
    if (
        not isinstance(receipt, CBORTag)
        or receipt.tag != cwt.const.COSE_TYPE_TO_TAG[cwt.const.COSETypes.SIGN1]
        or type(receipt.value) is not list
        or len(receipt.value) != 4
    ):
        raise ValueError("Receipt must be a tagged four-element COSE Sign1 message")
    phdr_bytes, uhdr, payload, signature = receipt.value
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
        if type(proof_list) is not list or not proof_list:
            raise ValueError("Proofs must be nonempty arrays of bstr")
        if any(type(proof) is not bytes for proof in proof_list):
            raise ValueError("Proofs must be nonempty arrays of bstr")
    if COSE_RECEIPT_INCLUSION_PROOF_LABEL not in proofs:
        raise ValueError("Inclusion proof is required")

    signed_root = b""
    for inclusion_proof in proofs[COSE_RECEIPT_INCLUSION_PROOF_LABEL]:
        proof = _require_map(
            _decode_receipt_cbor(inclusion_proof),
            "Inclusion proof",
            {CCF_PROOF_LEAF_LABEL, CCF_PROOF_PATH_LABEL},
        )
        leaf = proof[CCF_PROOF_LEAF_LABEL]
        if type(leaf) is not list or len(leaf) != 3:
            raise ValueError("Leaf must be a three-element array")
        _require_digest(leaf[0])
        _require_digest(leaf[2])
        if type(leaf[1]) is not str or not 1 <= len(leaf[1].encode("utf-8")) <= 1024:
            raise ValueError("Commit evidence must be a tstr of 1..1024 UTF-8 bytes")
        if claim_digest != leaf[2]:
            raise ValueError(f"Claim digest mismatch: {leaf[2]!r} != {claim_digest!r}")
        accumulator = sha256(
            leaf[0] + sha256(leaf[1].encode()).digest() + leaf[2]
        ).digest()
        accumulator = _fold_path(accumulator, _proof_path(proof[CCF_PROOF_PATH_LABEL]))
        if signed_root and accumulator != signed_root:
            raise ValueError("Inclusion proofs reconstruct different roots")
        signed_root = accumulator

    for consistency_proof in proofs.get(COSE_RECEIPT_CONSISTENCY_PROOF_LABEL, []):
        proof = _require_map(
            _decode_receipt_cbor(consistency_proof),
            "Consistency proof",
            {CCF_PROOF_LEAF_LABEL, CCF_PROOF_PATH_LABEL},
        )
        anchor = proof[CCF_PROOF_LEAF_LABEL]
        _require_digest(anchor)
        path = _proof_path(proof[CCF_PROOF_PATH_LABEL], consistency=True)
        if _fold_path(anchor, path) != signed_root:
            raise ValueError("Consistency proof does not reconstruct the signed root")

    ic_phdr, _, _ = ccf.signatures._verify_cose_root_signature_with_key(
        key_pem.encode("ascii"), signed_root, receipt_bytes
    )
    return ic_phdr
