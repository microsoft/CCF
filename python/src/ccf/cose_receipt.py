# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import base64
from hashlib import sha256
from typing import List
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

import cbor2
from pycose.messages import Sign1Message
from ccf.cose import from_cryptography_eckey_obj


def root(leaf: str, proof: List[dict]):
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
    node_cert: Certificate, service_cert: Certificate, endorsements: List[Certificate]
):
    """
    Check a node certificate is endorsed by a service certificate, transitively through a list of endorsements.
    """
    cert_i = node_cert
    for endorsement in endorsements:
        check_endorsement(cert_i, endorsement)
        cert_i = endorsement
    check_endorsement(cert_i, service_cert)


def verify(receipt: bytes, service: Certificate):
    cose = cbor2.loads(receipt)
    assert cose.tag == 18
    assert len(cose.value) == 4
    uhdr = cose.value[1]
    assert 396 in uhdr
    proof = uhdr[396]
    assert -1 in proof
    inclusion_proofs = proof[-1]
    assert len(inclusion_proofs) == 1
    inclusion_proof = inclusion_proofs[0]
    inclusion_proof = cbor2.loads(inclusion_proof)
    leaf = inclusion_proof[1]
    accumulator = sha256(leaf[0] + sha256(leaf[1].encode()).digest() + leaf[2]).digest()
    path = inclusion_proof[2]
    for left, digest in path:
        if left:
            accumulator = sha256(digest + accumulator).digest()
        else:
            accumulator = sha256(accumulator + digest).digest()
    root = accumulator
    # Verify top-level signature
    msg = Sign1Message.decode(receipt)

    cose_key = from_cryptography_eckey_obj(service.public_key())
    msg.key = cose_key
    msg.verify_signature(root)


if __name__ == "__main__":
    with open(
        "/home/amchamay/CCF/build/workspace/cpp_e2e_logging_cft_common/receipt_2.139.cose",
        "rb",
    ) as f:
        receipt = f.read()
    with open(
        "/home/amchamay/CCF/build/workspace/cpp_e2e_logging_cft_common/service_cert.pem",
        "rb",
    ) as f:
        service_cert = load_pem_x509_certificate(f.read(), default_backend())
    verify(receipt, service_cert)
