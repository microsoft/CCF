# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import base64
from hashlib import sha256

import cbor2
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
    COSE_RECEIPT_INCLUSION_PROOF_LABEL,
    key_fingerprint_from_key,
)


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
    Verify a COSE Sign1 receipt as defined in https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/,
    using the CCF tree algorithm defined in https://datatracker.ietf.org/doc/draft-birkholz-cose-receipts-ccf-profile/

    """
    key_pem = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(
        "ascii"
    )
    expected_kid = key_fingerprint_from_key(key_pem)

    receipt = cbor2.loads(receipt_bytes)
    if receipt.tag != cwt.const.COSE_TYPE_TO_TAG[cwt.const.COSETypes.SIGN1]:
        raise ValueError(f"Receipt must be a COSE Sign1 message, got tag {receipt.tag}")
    phdr, uhdr, _payload, _sig = receipt.value
    phdr = cbor2.loads(phdr)

    if phdr.get(int(cwt.COSEHeaders.KID)) != expected_kid.encode("utf-8"):
        raise ValueError(f"Receipt is not signed by the expected key {expected_kid}")

    if COSE_PHDR_VDS_LABEL not in phdr:
        raise ValueError("Verifiable data structure type is required")
    if phdr[COSE_PHDR_VDS_LABEL] != COSE_PHDR_VDS_CCF_LEDGER_SHA256:
        raise ValueError("vds(395) protected header must be CCF_LEDGER_SHA256(2)")

    if COSE_PHDR_VDP_LABEL not in uhdr:
        raise ValueError("Verifiable data proof is required")
    proof = uhdr[COSE_PHDR_VDP_LABEL]
    if COSE_RECEIPT_INCLUSION_PROOF_LABEL not in proof:
        raise ValueError("Inclusion proof is required")
    inclusion_proofs = proof[COSE_RECEIPT_INCLUSION_PROOF_LABEL]
    if not inclusion_proofs:
        raise ValueError("At least one inclusion proof is required")

    ic_phdr = None
    for inclusion_proof in inclusion_proofs:
        if not isinstance(inclusion_proof, bytes):
            raise TypeError("Inclusion proof must be bstr")
        proof = cbor2.loads(inclusion_proof)
        if CCF_PROOF_LEAF_LABEL not in proof:
            raise ValueError("Leaf must be present")
        leaf = proof[CCF_PROOF_LEAF_LABEL]
        if claim_digest != leaf[2]:
            raise ValueError(f"Claim digest mismatch: {leaf[2]!r} != {claim_digest!r}")
        accumulator = sha256(
            leaf[0] + sha256(leaf[1].encode()).digest() + leaf[2]
        ).digest()
        if CCF_PROOF_PATH_LABEL not in proof:
            raise ValueError("Path must be present")
        path = proof[CCF_PROOF_PATH_LABEL]
        for left, digest in path:
            if left:
                accumulator = sha256(digest + accumulator).digest()
            else:
                accumulator = sha256(accumulator + digest).digest()
        ic_phdr, _, _ = ccf.signatures._verify_cose_root_signature_with_key(
            key_pem.encode("ascii"), accumulator, receipt_bytes
        )
    return ic_phdr
