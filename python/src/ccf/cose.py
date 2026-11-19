# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import base64
import hashlib
import json
import sys
import warnings
from collections.abc import Mapping
from datetime import datetime
from typing import Any, TypedDict, cast

import cbor2
import cwt
import cwt.const
import cwt.enums
import cwt.utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificatePublicKeyTypes,
    PublicKeyTypes,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
    load_pem_public_key,
)
from cryptography.x509 import load_pem_x509_certificate

Pem = str


class PreparedCoseSign1(TypedDict):
    """Algorithm and base64-encoded digest to send to an external signer.

    The algorithm is a JSON Web Algorithm name, such as ``"ES384"``, as
    expected by the Azure Key Vault sign operation.
    """

    alg: str
    value: str


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
COSE_RECEIPT_CONSISTENCY_PROOF_LABEL = -2

# See https://datatracker.ietf.org/doc/draft-birkholz-cose-receipts-ccf-profile/

CCF_PROOF_LEAF_LABEL = 1
CCF_PROOF_PATH_LABEL = 2

# See https://datatracker.ietf.org/doc/draft-ietf-scitt-receipts-ccf-profile/

CCF_CONSISTENCY_PROOF_ANCHOR_LABEL = 1
CCF_CONSISTENCY_PROOF_PATH_LABEL = 2
CCF_MAX_COMMIT_EVIDENCE_SIZE = 1024

# Pure ML-DSA COSE algorithms, see https://www.rfc-editor.org/rfc/rfc9964.html

COSE_ALG_ML_DSA_44 = -48
COSE_ALG_ML_DSA_65 = -49
COSE_ALG_ML_DSA_87 = -50

# Digest algorithm and JSON Web Algorithm name for each supported COSE
# signature algorithm (RFC 9053, section 2.1).
_COSE_ALG_HASHES: dict[int, type[hashes.HashAlgorithm]] = {
    cwt.enums.COSEAlgs.ES256: hashes.SHA256,
    cwt.enums.COSEAlgs.ES384: hashes.SHA384,
    cwt.enums.COSEAlgs.ES512: hashes.SHA512,
}
_COSE_ALG_NAMES: dict[int, str] = {
    cwt.enums.COSEAlgs.ES256: "ES256",
    cwt.enums.COSEAlgs.ES384: "ES384",
    cwt.enums.COSEAlgs.ES512: "ES512",
}


def default_algorithm_for_key(key: CertificatePublicKeyTypes) -> int:
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


def cert_fingerprint(cert_pem: Pem) -> bytes:
    """Return the hexadecimal SHA-256 certificate fingerprint as UTF-8 bytes."""
    cert = load_pem_x509_certificate(cert_pem.encode("ascii"))
    return cert.fingerprint(hashes.SHA256()).hex().encode("utf-8")


def key_fingerprint_from_cert(cert_pem: Pem) -> str:
    """Return the hexadecimal SHA-256 fingerprint of a certificate's public key."""
    cert = load_pem_x509_certificate(cert_pem.encode("ascii"))
    pub_key = cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(pub_key).hexdigest()


def key_fingerprint_from_key(key_pem: Pem) -> str:
    """Return the hexadecimal SHA-256 fingerprint of a PEM public key."""
    key = load_pem_public_key(key_pem.encode("ascii"))
    pub_key = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(pub_key).hexdigest()


def create_cose_sign1(
    payload: bytes,
    key_priv_pem: Pem,
    cert_pem: Pem,
    additional_protected_header: Mapping[Any, Any] | None = None,
) -> bytes:
    """Sign a payload with the supplied PEM private key and certificate."""
    cose_ctx = cwt.COSE.new(alg_auto_inclusion=True, deterministic_header=True)
    cose_key = cwt.COSEKey.from_pem(key_priv_pem, kid=cert_fingerprint(cert_pem))
    # kid is passed explicitly in the protected header, because kid_auto_inclusion
    # sets the kid in the unprotected header
    phdr: dict[Any, Any] = {int(cwt.COSEHeaders.KID): cert_fingerprint(cert_pem)}
    additional_header = additional_protected_header or {}
    phdr.update(additional_header)
    encoded = cose_ctx.encode_and_sign(
        payload, cose_key, protected=cwt.utils.ResolvedHeader(phdr)
    )
    if not isinstance(encoded, bytes):
        raise TypeError("Expected an encoded COSE Sign1 byte string")
    return encoded


def create_cose_sign1_prepare(
    payload: bytes,
    cert_pem: Pem,
    additional_protected_header: Mapping[Any, Any] | None = None,
) -> PreparedCoseSign1:
    """Prepare a digest and algorithm identifier for an external signer.

    The digest is computed with the hash function of the signing algorithm
    implied by the certificate's public key.
    """
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

    digester = hashes.Hash(_COSE_ALG_HASHES[alg]())
    digester.update(tbs)
    digest = digester.finalize()
    return {"alg": _COSE_ALG_NAMES[alg], "value": base64.b64encode(digest).decode()}


def create_cose_sign1_finish(
    payload: bytes,
    cert_pem: Pem,
    signature: str | bytes,
    additional_protected_header: Mapping[Any, Any] | None = None,
) -> bytes:
    """Finish a COSE Sign1 message using a base64url-encoded signature."""
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
        cwt.const.COSE_TYPE_TO_TAG[cwt.COSETypes.SIGN1],
        [phdr_encoded, {}, payload, sig],
    )
    return cbor2.dumps(msg)


def verify_cose_sign1_with_cert(
    certificate: bytes,
    cose_sign1: bytes,
    use_key: bool = True,
    payload: bytes | None = None,
) -> tuple[dict[str | int, Any], dict[str | int, Any], bytes]:
    """Verify a COSE Sign1 message and return its headers and payload."""
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


_COSE_SIGN1_TAG = cwt.const.COSE_TYPE_TO_TAG[cwt.COSETypes.SIGN1]


def _decode_cose_sign1(value: Any, _immutable: bool) -> cbor2.CBORTag:
    """Decode a COSE_Sign1 tag. Registering it keeps the contents of the
    message a mutable array and map, which cbor2 decodes as immutable
    containers for other tags."""
    return cbor2.CBORTag(_COSE_SIGN1_TAG, value)


def _is_mldsa_key(key: PublicKeyTypes) -> bool:
    """Return whether key is an ML-DSA public key."""
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError:  # cryptography < 47 has no ML-DSA
        return False
    return isinstance(
        key, (mldsa.MLDSA44PublicKey, mldsa.MLDSA65PublicKey, mldsa.MLDSA87PublicKey)
    )


def verify_cose_sign1_mldsa(
    spki_der: bytes, cose_sign1: bytes, payload: bytes | None = None
) -> tuple[dict[str | int, Any], dict[str | int, Any], bytes]:
    """Verify a COSE Sign1 message signed with pure ML-DSA (RFC 9964), and
    return its protected headers, unprotected headers and payload.

    spki_der is the DER-encoded SubjectPublicKeyInfo of the ML-DSA public key.
    The protected alg must be the algorithm of its parameter set, and a kid, if
    present, the hexadecimal SHA-256 of the key's DER encoding.
    payload is the detached payload, for a message with a nil payload.
    ML-DSA requires cryptography 48 or later. Raises TypeError if the key is
    not an ML-DSA key, and ValueError if the message is malformed or not signed
    by the key.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError as exc:  # cryptography < 47 has no ML-DSA
        raise ValueError("ML-DSA verification requires cryptography >= 48") from exc

    key = load_der_public_key(spki_der)
    if isinstance(key, mldsa.MLDSA44PublicKey):
        alg = COSE_ALG_ML_DSA_44
    elif isinstance(key, mldsa.MLDSA65PublicKey):
        alg = COSE_ALG_ML_DSA_65
    elif isinstance(key, mldsa.MLDSA87PublicKey):
        alg = COSE_ALG_ML_DSA_87
    else:
        raise TypeError("Key is not an ML-DSA public key")

    try:
        message = cbor2.loads(
            cose_sign1, semantic_decoders={_COSE_SIGN1_TAG: _decode_cose_sign1}
        )
    except cbor2.CBORDecodeError as exc:
        raise ValueError(f"Invalid COSE Sign1 CBOR: {exc}") from exc
    if type(message) is not cbor2.CBORTag or message.tag != _COSE_SIGN1_TAG:
        raise ValueError("Message must be a tagged four-element COSE Sign1 message")
    elements = cast(list[Any], message.value)
    if type(elements) is not list or len(elements) != 4:
        raise ValueError("Message must be a tagged four-element COSE Sign1 message")
    phdr_bytes, uhdr, message_payload, signature = elements
    if type(phdr_bytes) is not bytes or type(signature) is not bytes:
        raise ValueError("Protected header and signature must be bstr")
    try:
        protected = cast(dict[str | int, Any], cbor2.loads(phdr_bytes))
    except cbor2.CBORDecodeError as exc:
        raise ValueError(f"Invalid protected header CBOR: {exc}") from exc
    if type(protected) is not dict:
        raise ValueError("Protected header must be a map")
    unprotected = cast(dict[str | int, Any], uhdr)
    if type(unprotected) is not dict:
        raise ValueError("Unprotected header must be a map")

    if protected.get(int(cwt.COSEHeaders.ALG)) != alg:
        raise ValueError(f"Protected alg must be {alg} for this ML-DSA key")
    kid = protected.get(
        int(cwt.COSEHeaders.KID), unprotected.get(int(cwt.COSEHeaders.KID))
    )
    expected_kid = hashlib.sha256(
        key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ).hexdigest()
    if kid is not None and kid != expected_kid.encode("ascii"):
        raise ValueError(f"Message is not signed by the expected key {expected_kid}")

    if payload is None:
        if type(message_payload) is not bytes:
            raise ValueError("Payload is detached")
        payload = message_payload
    elif message_payload is not None:
        raise ValueError("Payload must be detached (nil)")

    to_be_signed = cbor2.dumps(["Signature1", phdr_bytes, b"", payload])
    try:
        key.verify(signature, to_be_signed)
    except InvalidSignature as exc:
        raise ValueError("ML-DSA signature verification failed") from exc
    return protected, unprotected, payload


def verify_cose_sign1_with_key(
    key: bytes, cose_sign1: bytes, payload: bytes | None = None
) -> tuple[dict[str | int, Any], dict[str | int, Any], bytes]:
    """Verify a COSE Sign1 message using a PEM public key.

    ML-DSA keys are verified with :func:`verify_cose_sign1_mldsa`.
    """
    public_key = load_pem_public_key(key)
    if _is_mldsa_key(public_key):
        return verify_cose_sign1_mldsa(
            public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo),
            cose_sign1,
            payload,
        )
    cose_ctx = cwt.COSE.new()
    key_pem = key.decode()
    cose_key = cwt.COSEKey.from_pem(key_pem, kid=key_fingerprint_from_key(key_pem))
    return cose_ctx.decode_with_headers(cose_sign1, cose_key, detached_payload=payload)


def verify_receipt(
    receipt_bytes: bytes, key: CertificatePublicKeyTypes, claim_digest: bytes
):
    """
    Verify a COSE Sign1 receipt as defined in https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/,
    using the CCF tree algorithm defined in https://datatracker.ietf.org/doc/draft-birkholz-cose-receipts-ccf-profile/

    Deprecated: use ccf.receipt.verify_cose instead.
    """
    warnings.warn(
        "ccf.cose.verify_receipt is deprecated; use ccf.receipt.verify_cose instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    key_pem = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(
        "ascii"
    )
    expected_kid = key_fingerprint_from_key(key_pem)
    cose_key = cwt.COSEKey.from_pem(key_pem, kid=expected_kid)
    cose_ctx = cwt.COSE.new()

    receipt = cbor2.loads(receipt_bytes)
    assert receipt.tag == cwt.const.COSE_TYPE_TO_TAG[cwt.COSETypes.SIGN1]
    phdr, uhdr, _payload, _sig = receipt.value
    phdr = cbor2.loads(phdr)

    assert phdr[4] == expected_kid.encode("utf-8")

    assert COSE_PHDR_VDS_LABEL in phdr, "Verifiable data structure type is required"
    assert (
        phdr[COSE_PHDR_VDS_LABEL] == COSE_PHDR_VDS_CCF_LEDGER_SHA256
    ), "vds(395) protected header must be CCF_LEDGER_SHA256(2)"

    assert COSE_PHDR_VDP_LABEL in uhdr, "Verifiable data proof is required"
    proof = uhdr[COSE_PHDR_VDP_LABEL]
    assert COSE_RECEIPT_INCLUSION_PROOF_LABEL in proof, "Inclusion proof is required"
    inclusion_proofs = proof[COSE_RECEIPT_INCLUSION_PROOF_LABEL]
    assert inclusion_proofs, "At least one inclusion proof is required"

    ic_phdr = None
    for inclusion_proof in inclusion_proofs:
        assert isinstance(inclusion_proof, bytes), "Inclusion proof must be bstr"
        proof = cbor2.loads(inclusion_proof)
        assert CCF_PROOF_LEAF_LABEL in proof, "Leaf must be present"
        leaf = proof[CCF_PROOF_LEAF_LABEL]
        if claim_digest != leaf[2]:
            raise ValueError(f"Claim digest mismatch: {leaf[2]!r} != {claim_digest!r}")
        accumulator = hashlib.sha256(
            leaf[0] + hashlib.sha256(leaf[1].encode()).digest() + leaf[2]
        ).digest()
        assert CCF_PROOF_PATH_LABEL in proof, "Path must be present"
        path = proof[CCF_PROOF_PATH_LABEL]
        for left, digest in path:
            if left:
                accumulator = hashlib.sha256(digest + accumulator).digest()
            else:
                accumulator = hashlib.sha256(accumulator + digest).digest()
        ic_phdr, _, _ = cose_ctx.decode_with_headers(
            receipt_bytes, cose_key, detached_payload=accumulator
        )
    return ic_phdr


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


def _common_parser(description: str) -> argparse.ArgumentParser:
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
