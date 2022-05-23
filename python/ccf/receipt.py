# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import base64
from hashlib import sha256
from typing import List
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


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
