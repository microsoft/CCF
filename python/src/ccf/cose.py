# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import base64
import hashlib
import io
import json
import sys
from datetime import datetime
from typing import Any

import cbor2
import cwt
import cwt.const
import cwt.exceptions
import cwt.enums
import cwt.utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
    load_der_public_key,
)
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.base import CertificatePublicKeyTypes
from ccf.tx_id import TxID

Pem = str

GOV_MSG_TYPES_WITH_PROPOSAL_ID = ["ballot", "withdrawal"]

GOV_MSG_TYPES = [
    "proposal",
    "ack",
    "state_digest",
    "recovery_share",
    "encrypted_recovery_share",
] + GOV_MSG_TYPES_WITH_PROPOSAL_ID

# See https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/

COSE_PHDR_VDP_LABEL = 396
COSE_PHDR_VDS_LABEL = 395
COSE_PHDR_VDS_CCF_LEDGER_SHA256 = 2
COSE_RECEIPT_INCLUSION_PROOF_LABEL = -1

# See https://datatracker.ietf.org/doc/draft-birkholz-cose-receipts-ccf-profile/

CCF_PROOF_LEAF_LABEL = 1
CCF_PROOF_PATH_LABEL = 2

CCF_V1_LABEL = "ccf.v1"
CCF_ENDORSEMENT_RANGE_BEGIN = "epoch.start.txid"
CCF_ENDORSEMENT_RANGE_END = "epoch.end.txid"
RECOVERY_VIEW_CHANGE = 2
MAX_SNAPSHOT_ENDORSEMENTS_SIZE = 16 * 1024 * 1024
MAX_SNAPSHOT_ENDORSEMENTS_COUNT = 64
MIN_SNAPSHOT_ENDORSEMENT_SIZE = 64
MAX_SNAPSHOT_ENDORSEMENT_SIZE = 1024 * 1024
MAX_SNAPSHOT_ENDORSEMENTS_PAYLOAD_SIZE = 4 * 1024 * 1024


def default_algorithm_for_key(key) -> int:
    """
    Get the default algorithm for a given key, based on its
    type and parameters.
    """
    if isinstance(key, EllipticCurvePublicKey):
        if isinstance(key.curve, ec.SECP256R1):
            return cwt.enums.COSEAlgs.ES256
        elif isinstance(key.curve, ec.SECP384R1):
            return cwt.enums.COSEAlgs.ES384
        elif isinstance(key.curve, ec.SECP521R1):
            return cwt.enums.COSEAlgs.ES512
        else:
            raise NotImplementedError("unsupported curve")
    else:
        raise NotImplementedError("unsupported key type")


def get_priv_key_type(priv_pem: Pem) -> str:
    key = load_pem_private_key(priv_pem.encode("ascii"), None)
    if isinstance(key, EllipticCurvePrivateKey):
        return "ec"
    raise NotImplementedError("unsupported key type")


def cert_fingerprint(cert_pem: Pem):
    cert = load_pem_x509_certificate(cert_pem.encode("ascii"))
    return cert.fingerprint(hashes.SHA256()).hex().encode("utf-8")


def key_fingerprint_from_cert(cert_pem: Pem):
    cert = load_pem_x509_certificate(cert_pem.encode("ascii"))
    pub_key = cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(pub_key).hexdigest()


def key_fingerprint_from_key(key_pem: Pem):
    key = load_pem_public_key(key_pem.encode("ascii"))
    pub_key = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(pub_key).hexdigest()


def create_cose_sign1(
    payload: bytes,
    key_priv_pem: Pem,
    cert_pem: Pem,
    additional_protected_header: dict | None = None,
) -> bytes:
    cose_ctx = cwt.COSE.new(alg_auto_inclusion=True, deterministic_header=True)
    cose_key = cwt.COSEKey.from_pem(key_priv_pem, kid=cert_fingerprint(cert_pem))
    # kid is passed explicitly in the protected header, because kid_auto_inclusion
    # sets the kid in the unprotected header
    phdr: dict[Any, Any] = {int(cwt.COSEHeaders.KID): cert_fingerprint(cert_pem)}
    additional_header = additional_protected_header or {}
    phdr.update(additional_header)
    return cose_ctx.encode_and_sign(
        payload, cose_key, protected=cwt.utils.ResolvedHeader(phdr)
    )


def create_cose_sign1_prepare(
    payload: bytes,
    cert_pem: Pem,
    additional_protected_header: dict | None = None,
) -> dict:
    cert = load_pem_x509_certificate(cert_pem.encode("ascii"))
    alg = default_algorithm_for_key(cert.public_key())
    kid = cert_fingerprint(cert_pem)

    protected_header: dict[str | int, Any] = {
        int(cwt.COSEHeaders.ALG): alg,
        int(cwt.COSEHeaders.KID): kid,
    }
    protected_header.update(additional_protected_header or {})
    protected_header = cwt.utils.sort_keys_for_deterministic_encoding(protected_header)
    phdr_encoded = cbor2.dumps(protected_header)
    tbs = cbor2.dumps(["Signature1", phdr_encoded, b"", payload])

    assert cert.signature_hash_algorithm
    digester = hashes.Hash(cert.signature_hash_algorithm)
    digester.update(tbs)
    digest = digester.finalize()
    return {"alg": alg, "value": base64.b64encode(digest).decode()}


def create_cose_sign1_finish(
    payload: bytes,
    cert_pem: Pem,
    signature: str,
    additional_protected_header: dict | None = None,
) -> bytes:
    cert = load_pem_x509_certificate(cert_pem.encode("ascii"))
    alg = default_algorithm_for_key(cert.public_key())
    kid = cert_fingerprint(cert_pem)

    protected_header: dict[str | int, Any] = {
        int(cwt.COSEHeaders.ALG): alg,
        int(cwt.COSEHeaders.KID): kid,
    }
    protected_header.update(additional_protected_header or {})
    protected_header = cwt.utils.sort_keys_for_deterministic_encoding(protected_header)
    phdr_encoded = cbor2.dumps(protected_header)

    sig = base64.urlsafe_b64decode(signature)
    assert isinstance(sig, bytes)
    msg = cbor2.CBORTag(
        cwt.const.COSE_TYPE_TO_TAG[cwt.const.COSETypes.SIGN1],
        [phdr_encoded, {}, payload, sig],
    )
    return cbor2.dumps(msg)


def verify_cose_sign1_with_cert(certificate, cose_sign1, use_key=True, payload=None):
    cose_ctx = cwt.COSE.new()
    cert_pem = certificate.decode()
    cose_key = cwt.COSEKey.from_pem(
        cert_pem,
        kid=(
            key_fingerprint_from_cert(cert_pem)
            if use_key
            else cert_fingerprint(cert_pem)
        ),
    )
    return cose_ctx.decode_with_headers(cose_sign1, cose_key, detached_payload=payload)


def verify_cose_sign1_with_key(key, cose_sign1, payload=None):
    cose_ctx = cwt.COSE.new()
    key_pem = key.decode()
    cose_key = cwt.COSEKey.from_pem(key_pem, kid=key_fingerprint_from_key(key_pem))
    return cose_ctx.decode_with_headers(cose_sign1, cose_key, detached_payload=payload)


def _validate_cose_endorsement_resource_limits(
    endorsements: list[bytes],
) -> None:
    if not 1 <= len(endorsements) <= MAX_SNAPSHOT_ENDORSEMENTS_COUNT:
        raise ValueError(
            "Snapshot endorsements sidecar must contain between 1 and "
            f"{MAX_SNAPSHOT_ENDORSEMENTS_COUNT} endorsements, got "
            f"{len(endorsements)}"
        )

    payload_size = 0
    for index, endorsement in enumerate(endorsements):
        endorsement_size = len(endorsement)
        if endorsement_size < MIN_SNAPSHOT_ENDORSEMENT_SIZE:
            raise ValueError(
                f"Snapshot endorsement at index {index} is too small "
                f"({endorsement_size} bytes; minimum "
                f"{MIN_SNAPSHOT_ENDORSEMENT_SIZE} bytes)"
            )
        if endorsement_size > MAX_SNAPSHOT_ENDORSEMENT_SIZE:
            raise ValueError(
                f"Snapshot endorsement at index {index} is too large "
                f"({endorsement_size} bytes; maximum "
                f"{MAX_SNAPSHOT_ENDORSEMENT_SIZE} bytes)"
            )
        payload_size += endorsement_size
        if payload_size > MAX_SNAPSHOT_ENDORSEMENTS_PAYLOAD_SIZE:
            raise ValueError(
                "Snapshot endorsements payload is too large "
                f"(maximum {MAX_SNAPSHOT_ENDORSEMENTS_PAYLOAD_SIZE} bytes)"
            )


def _decode_cbor_length(
    serialized: memoryview, offset: int, expected_major_type: int
) -> tuple[int, int]:
    if offset >= len(serialized):
        raise ValueError("Truncated snapshot endorsements CBOR")

    initial_byte = serialized[offset]
    offset += 1
    if initial_byte >> 5 != expected_major_type:
        raise ValueError("Unexpected snapshot endorsements CBOR type")

    additional_info = initial_byte & 0x1F
    if additional_info < 24:
        return additional_info, offset

    length_byte_count = {24: 1, 25: 2, 26: 4, 27: 8}.get(additional_info)
    if length_byte_count is None:
        raise ValueError("Indefinite or invalid snapshot endorsements CBOR length")
    end = offset + length_byte_count
    if end > len(serialized):
        raise ValueError("Truncated snapshot endorsements CBOR length")
    return int.from_bytes(serialized[offset:end]), end


def serialize_cose_endorsements(endorsements: list[bytes]) -> bytes:
    if not all(isinstance(endorsement, bytes) for endorsement in endorsements):
        raise TypeError("COSE endorsements must be bytes")
    _validate_cose_endorsement_resource_limits(endorsements)
    serialized = cbor2.dumps(endorsements)
    if len(serialized) > MAX_SNAPSHOT_ENDORSEMENTS_SIZE:
        raise ValueError(
            "Snapshot endorsements sidecar is too large "
            f"({len(serialized)} bytes; maximum "
            f"{MAX_SNAPSHOT_ENDORSEMENTS_SIZE} bytes)"
        )
    return serialized


def deserialize_cose_endorsements(serialized: bytes) -> list[bytes]:
    try:
        data = memoryview(serialized)
    except TypeError as e:
        raise TypeError("Snapshot endorsements CBOR must be bytes-like") from e
    if len(data) > MAX_SNAPSHOT_ENDORSEMENTS_SIZE:
        raise ValueError(
            "Snapshot endorsements sidecar is too large "
            f"({len(data)} bytes; maximum {MAX_SNAPSHOT_ENDORSEMENTS_SIZE} bytes)"
        )

    try:
        endorsement_count, offset = _decode_cbor_length(data, 0, 4)
    except ValueError as e:
        raise ValueError("Snapshot endorsements must be a CBOR array") from e
    if not 1 <= endorsement_count <= MAX_SNAPSHOT_ENDORSEMENTS_COUNT:
        raise ValueError(
            "Snapshot endorsements sidecar must contain between 1 and "
            f"{MAX_SNAPSHOT_ENDORSEMENTS_COUNT} endorsements, got "
            f"{endorsement_count}"
        )

    endorsements: list[bytes] = []
    payload_size = 0
    for index in range(endorsement_count):
        try:
            endorsement_size, offset = _decode_cbor_length(data, offset, 2)
        except ValueError as e:
            raise ValueError(
                "Snapshot endorsements must be a CBOR array of byte strings"
            ) from e
        if endorsement_size < MIN_SNAPSHOT_ENDORSEMENT_SIZE:
            raise ValueError(
                f"Snapshot endorsement at index {index} is too small "
                f"({endorsement_size} bytes; minimum "
                f"{MIN_SNAPSHOT_ENDORSEMENT_SIZE} bytes)"
            )
        if endorsement_size > MAX_SNAPSHOT_ENDORSEMENT_SIZE:
            raise ValueError(
                f"Snapshot endorsement at index {index} is too large "
                f"({endorsement_size} bytes; maximum "
                f"{MAX_SNAPSHOT_ENDORSEMENT_SIZE} bytes)"
            )
        payload_size += endorsement_size
        if payload_size > MAX_SNAPSHOT_ENDORSEMENTS_PAYLOAD_SIZE:
            raise ValueError(
                "Snapshot endorsements payload is too large "
                f"(maximum {MAX_SNAPSHOT_ENDORSEMENTS_PAYLOAD_SIZE} bytes)"
            )
        end = offset + endorsement_size
        if end > len(data):
            raise ValueError(f"Snapshot endorsement at index {index} is truncated")
        endorsements.append(bytes(data[offset:end]))
        offset = end

    if offset != len(data):
        raise ValueError("Trailing data after snapshot endorsements CBOR array")
    return endorsements


def _get_required_integer_labeled_header(headers: dict, label: int, description: str):
    for actual_label, value in headers.items():
        if actual_label == label:
            if type(actual_label) is not int:
                raise ValueError(f"{description} label must be an integer")
            return value
    raise ValueError(f"{description} is required")


def _reject_unprotected_header(headers: dict, label: int, description: str):
    if any(actual_label == label for actual_label in headers):
        raise ValueError(f"{description} must not appear in unprotected headers")


def _validate_algorithm_and_kid_headers(
    protected: dict,
    unprotected: dict,
    key: CertificatePublicKeyTypes,
    description: str,
    expected_kid: bytes | None = None,
):
    if not isinstance(protected, dict):
        raise ValueError(f"{description} protected header must be a map")
    if not isinstance(unprotected, dict):
        raise ValueError(f"{description} unprotected header must be a map")

    algorithm_label = int(cwt.COSEHeaders.ALG)
    algorithm = _get_required_integer_labeled_header(
        protected, algorithm_label, f"{description} signing algorithm"
    )
    if type(algorithm) is not int:
        raise ValueError(f"{description} signing algorithm must be an integer")
    expected_algorithm = int(default_algorithm_for_key(key))
    if algorithm != expected_algorithm:
        raise ValueError(
            f"{description} signing algorithm {algorithm} does not match "
            f"verification key algorithm {expected_algorithm}"
        )
    _reject_unprotected_header(
        unprotected, algorithm_label, f"{description} signing algorithm"
    )

    if expected_kid is None:
        return

    kid_label = int(cwt.COSEHeaders.KID)
    kid = _get_required_integer_labeled_header(
        protected, kid_label, f"{description} key ID"
    )
    if not isinstance(kid, bytes) or kid != expected_kid:
        raise ValueError(f"{description} key ID does not match the verification key")
    _reject_unprotected_header(unprotected, kid_label, f"{description} key ID")


def verify_cose_endorsements(
    endorsements: list[bytes],
    target_key: CertificatePublicKeyTypes,
    snapshot_seqno: int,
) -> CertificatePublicKeyTypes:
    current_key = target_key
    ranges: list[tuple[TxID, TxID]] = []

    for index, endorsement in enumerate(endorsements):
        current_key_pem = current_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
        try:
            protected, unprotected, endorsed_key_der = verify_cose_sign1_with_key(
                current_key_pem, endorsement
            )
        except cwt.exceptions.CWTError as e:
            raise ValueError(
                f"COSE endorsement at index {index} failed signature verification"
            ) from e

        _validate_algorithm_and_kid_headers(
            protected,
            unprotected,
            current_key,
            f"COSE endorsement at index {index}",
        )

        ccf_headers = protected.get(CCF_V1_LABEL)
        if not isinstance(ccf_headers, dict):
            raise ValueError(
                f"COSE endorsement at index {index} has no {CCF_V1_LABEL} headers"
            )
        begin_header = ccf_headers.get(CCF_ENDORSEMENT_RANGE_BEGIN)
        end_header = ccf_headers.get(CCF_ENDORSEMENT_RANGE_END)
        if not isinstance(begin_header, str) or not isinstance(end_header, str):
            raise ValueError(
                f"COSE endorsement at index {index} has invalid epoch headers"
            )
        begin = TxID.from_str(begin_header)
        end = TxID.from_str(end_header)
        if not begin.valid() or not end.valid() or end.seqno < begin.seqno:
            raise ValueError(
                f"COSE endorsement at index {index} has an invalid epoch range"
            )
        if not isinstance(endorsed_key_der, bytes) or not endorsed_key_der:
            raise ValueError(
                f"COSE endorsement at index {index} contains no endorsed key"
            )

        ranges.append((begin, end))
        try:
            endorsed_key = load_der_public_key(endorsed_key_der)
        except ValueError as e:
            raise ValueError(
                f"COSE endorsement at index {index} contains an invalid public key"
            ) from e
        if not isinstance(endorsed_key, EllipticCurvePublicKey):
            raise ValueError(
                f"COSE endorsement at index {index} contains a non-EC public key"
            )
        current_key = endorsed_key

    for (newer_begin, _), (_, older_end) in zip(ranges, ranges[1:]):
        if (
            newer_begin.view - RECOVERY_VIEW_CHANGE != older_end.view
            or newer_begin.seqno - 1 != older_end.seqno
        ):
            raise ValueError(
                "COSE endorsement epoch ranges are not contiguous newest-to-oldest"
            )

    if ranges:
        oldest_begin, oldest_end = ranges[-1]
        if not oldest_begin.seqno <= snapshot_seqno <= oldest_end.seqno:
            raise ValueError(
                f"Oldest COSE endorsement range does not cover snapshot seqno {snapshot_seqno}"
            )

    return current_key


def verify_receipt_with_endorsements(
    receipt_bytes: bytes,
    target_key: CertificatePublicKeyTypes,
    claim_digest: bytes,
    endorsements: list[bytes],
    snapshot_seqno: int,
):
    snapshot_signer_key = verify_cose_endorsements(
        endorsements, target_key, snapshot_seqno
    )
    return verify_receipt(receipt_bytes, snapshot_signer_key, claim_digest)


def _decode_single_cbor(data: bytes, description: str):
    if not isinstance(data, bytes):
        raise TypeError(f"{description} CBOR must be bytes")

    stream = io.BytesIO(data)
    decoder = cbor2.CBORDecoder(stream)
    try:
        value = decoder.decode()
    except (cbor2.CBORDecodeError, EOFError) as e:
        raise ValueError(f"Invalid {description} CBOR") from e

    try:
        decoder.decode()
    except cbor2.CBORDecodeEOF:
        return value
    raise ValueError(f"Trailing data after {description} CBOR")


def verify_receipt(
    receipt_bytes: bytes, key: CertificatePublicKeyTypes, claim_digest: bytes
):
    """
    Verify a COSE Sign1 receipt as defined in https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/,
    using the CCF tree algorithm defined in https://datatracker.ietf.org/doc/draft-birkholz-cose-receipts-ccf-profile/

    """
    if not isinstance(claim_digest, bytes):
        raise TypeError("Claim digest must be bytes")
    if len(claim_digest) != hashlib.sha256().digest_size:
        raise ValueError(f"Claim digest must be {hashlib.sha256().digest_size} bytes")

    key_pem = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(
        "ascii"
    )
    expected_kid = key_fingerprint_from_key(key_pem)
    cose_key = cwt.COSEKey.from_pem(key_pem, kid=expected_kid)
    cose_ctx = cwt.COSE.new()

    receipt = _decode_single_cbor(receipt_bytes, "COSE receipt")
    expected_tag = cwt.const.COSE_TYPE_TO_TAG[cwt.const.COSETypes.SIGN1]
    if not isinstance(receipt, cbor2.CBORTag) or receipt.tag != expected_tag:
        raise ValueError(f"COSE receipt must use tag {expected_tag}")
    if not isinstance(receipt.value, (list, tuple)) or len(receipt.value) != 4:
        raise ValueError("COSE receipt must contain a four-element Sign1 array")

    protected_raw, unprotected, payload, signature = receipt.value
    if not isinstance(protected_raw, bytes):
        raise ValueError("COSE receipt protected header must be a byte string")
    if not isinstance(unprotected, dict):
        raise ValueError("COSE receipt unprotected header must be a map")
    if payload is not None:
        raise ValueError("COSE receipt payload must be detached")
    if not isinstance(signature, bytes) or not signature:
        raise ValueError("COSE receipt signature must be a non-empty byte string")

    protected = _decode_single_cbor(protected_raw, "COSE protected header")
    if not isinstance(protected, dict):
        raise ValueError("COSE receipt protected header must encode a map")

    _validate_algorithm_and_kid_headers(
        protected,
        unprotected,
        key,
        "COSE receipt",
        expected_kid.encode("utf-8"),
    )

    verifiable_data_structure = _get_required_integer_labeled_header(
        protected,
        COSE_PHDR_VDS_LABEL,
        "Verifiable data structure type",
    )
    if type(verifiable_data_structure) is not int:
        raise ValueError("Verifiable data structure type must be an integer")
    if verifiable_data_structure != COSE_PHDR_VDS_CCF_LEDGER_SHA256:
        raise ValueError("vds(395) protected header must be CCF_LEDGER_SHA256(2)")
    _reject_unprotected_header(
        unprotected,
        COSE_PHDR_VDS_LABEL,
        "Verifiable data structure type",
    )

    verifiable_data_proof = _get_required_integer_labeled_header(
        unprotected, COSE_PHDR_VDP_LABEL, "Verifiable data proof"
    )
    if not isinstance(verifiable_data_proof, dict):
        raise ValueError("Verifiable data proof must be a map")
    inclusion_proofs = _get_required_integer_labeled_header(
        verifiable_data_proof,
        COSE_RECEIPT_INCLUSION_PROOF_LABEL,
        "Inclusion proofs",
    )
    if not isinstance(inclusion_proofs, (list, tuple)):
        raise ValueError("Inclusion proofs must be an array")
    if not inclusion_proofs:
        raise ValueError("At least one inclusion proof is required")

    verified_protected_header = None
    for proof_index, inclusion_proof in enumerate(inclusion_proofs):
        if not isinstance(inclusion_proof, bytes) or not inclusion_proof:
            raise ValueError(
                f"Inclusion proof at index {proof_index} must be a non-empty "
                "byte string"
            )
        proof = _decode_single_cbor(inclusion_proof, "inclusion proof")
        if not isinstance(proof, dict):
            raise ValueError("Inclusion proof must encode a map")

        leaf = _get_required_integer_labeled_header(
            proof, CCF_PROOF_LEAF_LABEL, "Inclusion proof leaf"
        )
        if not isinstance(leaf, (list, tuple)) or len(leaf) != 3:
            raise ValueError("Inclusion proof leaf must contain three elements")
        write_set_digest, commit_evidence, proof_claim_digest = leaf
        if (
            not isinstance(write_set_digest, bytes)
            or len(write_set_digest) != hashlib.sha256().digest_size
        ):
            raise ValueError("Write set digest must be a 32-byte byte string")
        if not isinstance(commit_evidence, str) or not commit_evidence:
            raise ValueError("Commit evidence must be a non-empty string")
        if (
            not isinstance(proof_claim_digest, bytes)
            or len(proof_claim_digest) != hashlib.sha256().digest_size
        ):
            raise ValueError("Proof claim digest must be a 32-byte byte string")
        if claim_digest != proof_claim_digest:
            raise ValueError(
                f"Claim digest mismatch: {proof_claim_digest!r} != {claim_digest!r}"
            )
        accumulator = hashlib.sha256(
            write_set_digest
            + hashlib.sha256(commit_evidence.encode()).digest()
            + proof_claim_digest
        ).digest()

        path = _get_required_integer_labeled_header(
            proof, CCF_PROOF_PATH_LABEL, "Inclusion proof path"
        )
        if not isinstance(path, (list, tuple)):
            raise ValueError("Inclusion proof path must be an array")
        for path_index, path_entry in enumerate(path):
            if not isinstance(path_entry, (list, tuple)) or len(path_entry) != 2:
                raise ValueError(
                    f"Inclusion proof path entry {path_index} must contain "
                    "direction and digest"
                )
            left, digest = path_entry
            if not isinstance(left, bool):
                raise ValueError(
                    f"Inclusion proof path direction {path_index} must be boolean"
                )
            if (
                not isinstance(digest, bytes)
                or len(digest) != hashlib.sha256().digest_size
            ):
                raise ValueError(
                    f"Inclusion proof path digest {path_index} must be 32 bytes"
                )
            if left:
                accumulator = hashlib.sha256(digest + accumulator).digest()
            else:
                accumulator = hashlib.sha256(accumulator + digest).digest()
        try:
            verified_protected_header, _, _ = cose_ctx.decode_with_headers(
                receipt_bytes, cose_key, detached_payload=accumulator
            )
        except cwt.exceptions.CWTError as e:
            raise ValueError("COSE receipt signature verification failed") from e

    return verified_protected_header


_SIGN_DESCRIPTION = """Create and sign a COSE Sign1 message for CCF governance

Note that this tool writes binary COSE Sign1 to standard output.

This is done intentionally to facilitate passing the output directly to curl,
without having to create and read a temporary file on disk. For example:

ccf_cose_sign1 --content ... | curl http://... -H 'Content-Type: application/cose' --data-binary @-
"""

_PREPARE_DESCRIPTION = """Create the pre-hashed, to-be-signed digest for a CCF governance COSE Sign1 message.

This is a partial version of ccf_cose_sign1, modified for the purposes of offline signing, for example with AKV.

Unlike ccf_cose_sign1, this does not take a signing key, but returns a JSON object containing a signing algorithm,
and a base64-encoded digest. This can be passed directly to AKV for signing.
"""

_FINISH_DESCRIPTION = """Create a COSE Sign1 message for CCF governance with an externally provided signature.

Note that this tool writes binary COSE Sign1 to standard output.

This is done intentionally to facilitate passing the output directly to curl,
without having to create and read a temporary file on disk. For example:

ccf_cose_sign1_finish --content ... | curl http://... -H 'Content-Type: application/cose' --data-binary @-
"""


def _common_parser(description):
    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--content",
        help="Path to content file, or '-' for stdin",
        type=str,
        required=True,
    )
    parser.add_argument(
        "--signing-cert",
        help="Path to signing key, PEM-encoded",
        type=str,
        required=True,
    )
    parser.add_argument(
        "--ccf-gov-msg-type",
        help="ccf.gov.msg.type protected header",
        choices=GOV_MSG_TYPES,
        type=str,
        required=True,
    )
    parser.add_argument(
        "--ccf-gov-msg-proposal-id",
        "--ccf-gov-msg-proposal_id",
        help="ccf.gov.msg.proposal_id protected header",
        type=str,
    )
    parser.add_argument(
        "--ccf-gov-msg-created-at",
        "--ccf-gov-msg-created_at",
        help="ccf.gov.msg.created_at protected header",
        required=True,
    )
    return parser


def _sign_parser():
    parser = _common_parser(_SIGN_DESCRIPTION)
    parser.add_argument(
        "--signing-key",
        help="Path to signing key, PEM-encoded",
        type=str,
        required=True,
    )
    return parser


def _finish_parser():
    parser = _common_parser(_FINISH_DESCRIPTION)
    parser.add_argument(
        "--signature",
        help='Path to JSON file with a "value" field containing a raw signature, base64-encoded',
        type=str,
        required=True,
    )
    return parser


def _prepare_parser():
    return _common_parser(_PREPARE_DESCRIPTION)


def sign_cli():
    args = _sign_parser().parse_args()

    if args.ccf_gov_msg_type in GOV_MSG_TYPES_WITH_PROPOSAL_ID:
        assert (
            args.ccf_gov_msg_proposal_id is not None
        ), f"Message type {args.ccf_gov_msg_type} requires a proposal id"

    with (
        open(args.content, "rb") if args.content != "-" else sys.stdin.buffer
    ) as content_:
        content = content_.read()

    with open(args.signing_key, "r", encoding="utf-8") as signing_key_:
        signing_key = signing_key_.read()

    with open(args.signing_cert, "r", encoding="utf-8") as signing_cert_:
        signing_cert = signing_cert_.read()

    protected_header = {"ccf.gov.msg.type": args.ccf_gov_msg_type}
    if args.ccf_gov_msg_proposal_id:
        protected_header["ccf.gov.msg.proposal_id"] = args.ccf_gov_msg_proposal_id

    created_at = datetime.fromisoformat(args.ccf_gov_msg_created_at)
    protected_header["ccf.gov.msg.created_at"] = int(created_at.timestamp())

    cose_sign1 = create_cose_sign1(content, signing_key, signing_cert, protected_header)
    sys.stdout.buffer.write(cose_sign1)


def prepare_cli():
    args = _prepare_parser().parse_args()

    if args.ccf_gov_msg_type in GOV_MSG_TYPES_WITH_PROPOSAL_ID:
        assert (
            args.ccf_gov_msg_proposal_id is not None
        ), f"Message type {args.ccf_gov_msg_type} requires a proposal id"

    with (
        open(args.content, "rb") if args.content != "-" else sys.stdin.buffer
    ) as content_:
        content = content_.read()

    with open(args.signing_cert, "r", encoding="utf-8") as signing_cert_:
        signing_cert = signing_cert_.read()

    protected_header = {"ccf.gov.msg.type": args.ccf_gov_msg_type}
    if args.ccf_gov_msg_proposal_id:
        protected_header["ccf.gov.msg.proposal_id"] = args.ccf_gov_msg_proposal_id

    created_at = datetime.fromisoformat(args.ccf_gov_msg_created_at)
    protected_header["ccf.gov.msg.created_at"] = int(created_at.timestamp())

    digest = create_cose_sign1_prepare(content, signing_cert, protected_header)
    json.dump(digest, sys.stdout)


def finish_cli():
    args = _finish_parser().parse_args()

    if args.ccf_gov_msg_type in GOV_MSG_TYPES_WITH_PROPOSAL_ID:
        assert (
            args.ccf_gov_msg_proposal_id is not None
        ), f"Message type {args.ccf_gov_msg_type} requires a proposal id"

    with (
        open(args.content, "rb") if args.content != "-" else sys.stdin.buffer
    ) as content_:
        content = content_.read()

    with open(args.signing_cert, "r", encoding="utf-8") as signing_cert_:
        signing_cert = signing_cert_.read()

    with open(args.signature, "r", encoding="utf-8") as signature_:
        signature = json.load(signature_)["value"]

    protected_header = {"ccf.gov.msg.type": args.ccf_gov_msg_type}
    if args.ccf_gov_msg_proposal_id:
        protected_header["ccf.gov.msg.proposal_id"] = args.ccf_gov_msg_proposal_id

    created_at = datetime.fromisoformat(args.ccf_gov_msg_created_at)
    protected_header["ccf.gov.msg.created_at"] = int(created_at.timestamp())

    cose_sign1 = create_cose_sign1_finish(
        content, signing_cert, signature, protected_header
    )
    sys.stdout.buffer.write(cose_sign1)
