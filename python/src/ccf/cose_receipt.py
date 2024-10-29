# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from hashlib import sha256
from cryptography.x509.base import CertificatePublicKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import cbor2
from pycose.messages import Sign1Message
from ccf.cose import from_cryptography_eckey_obj
from pycose.headers import KID


def verify(receipt_bytes: bytes, key: CertificatePublicKeyTypes):
    expected_kid = sha256(
        key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ).digest()
    receipt = Sign1Message.decode(receipt_bytes)
    assert 396 in receipt.uhdr
    proof = receipt.uhdr[396]
    assert -1 in proof
    inclusion_proofs = proof[-1]
    assert len(inclusion_proofs) == 1
    inclusion_proof = inclusion_proofs[0]
    details = cbor2.loads(inclusion_proof)
    assert 1 in details
    leaf = details[1]
    accumulator = sha256(leaf[0] + sha256(leaf[1].encode()).digest() + leaf[2]).digest()
    assert 2 in details
    path = details[2]
    for left, digest in path:
        if left:
            accumulator = sha256(digest + accumulator).digest()
        else:
            accumulator = sha256(accumulator + digest).digest()
    # Check kid against CCF header
    cose_key = from_cryptography_eckey_obj(key)
    assert receipt.phdr[KID] == expected_kid
    receipt.key = cose_key
    if not receipt.verify_signature(accumulator):
        raise ValueError("Signature verification failed")
