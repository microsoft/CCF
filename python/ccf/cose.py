# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import sys

from typing import Optional

import cbor2
import pycose.headers  # type: ignore
from pycose.keys.ec2 import EC2Key  # type: ignore
from pycose.keys.curves import P256, P384, P521  # type: ignore
from pycose.keys.keyparam import EC2KpCurve, EC2KpX, EC2KpY, EC2KpD  # type: ignore
from pycose.messages import Sign1Message  # type: ignore
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

Pem = str

GOV_MSG_TYPES_WITH_PROPOSAL_ID = ["ballot", "withdrawal"]

GOV_MSG_TYPES = ["proposal", "ack", "state_digest"] + GOV_MSG_TYPES_WITH_PROPOSAL_ID


def from_cryptography_eckey_obj(ext_key) -> EC2Key:
    """
    Returns an initialized COSE Key object of type EC2Key.
    :param ext_key: Python cryptography key.
    :return: an initialized EC key
    """
    if hasattr(ext_key, "private_numbers"):
        priv_nums = ext_key.private_numbers()
        pub_nums = priv_nums.public_numbers
    else:
        priv_nums = None
        pub_nums = ext_key.public_numbers()

    if pub_nums.curve.name == "secp256r1":
        curve = P256
    elif pub_nums.curve.name == "secp384r1":
        curve = P384
    elif pub_nums.curve.name == "secp521r1":
        curve = P521
    else:
        raise NotImplementedError("unsupported curve")

    cose_key = {}
    if pub_nums:
        cose_key.update(
            {
                EC2KpCurve: curve,
                EC2KpX: pub_nums.x.to_bytes(curve.size, "big"),
                EC2KpY: pub_nums.y.to_bytes(curve.size, "big"),
            }
        )
    if priv_nums:
        cose_key.update(
            {
                EC2KpD: priv_nums.private_value.to_bytes(curve.size, "big"),
            }
        )
    return EC2Key.from_dict(cose_key)


def default_algorithm_for_key(key) -> str:
    """
    Get the default algorithm for a given key, based on its
    type and parameters.
    """
    if isinstance(key, EllipticCurvePublicKey):
        if isinstance(key.curve, ec.SECP256R1):
            return "ES256"
        elif isinstance(key.curve, ec.SECP384R1):
            return "ES384"
        elif isinstance(key.curve, ec.SECP521R1):
            return "ES512"
        else:
            raise NotImplementedError("unsupported curve")
    else:
        raise NotImplementedError("unsupported key type")


def get_priv_key_type(priv_pem: Pem) -> str:
    key = load_pem_private_key(priv_pem.encode("ascii"), None, default_backend())
    if isinstance(key, EllipticCurvePrivateKey):
        return "ec"
    raise NotImplementedError("unsupported key type")


def cert_fingerprint(cert_pem: Pem):
    cert = load_pem_x509_certificate(cert_pem.encode("ascii"), default_backend())
    return cert.fingerprint(hashes.SHA256()).hex().encode("utf-8")


def create_cose_sign1(
    payload: bytes,
    key_priv_pem: Pem,
    cert_pem: Pem,
    additional_headers: Optional[dict] = None,
) -> bytes:
    key_type = get_priv_key_type(key_priv_pem)

    cert = load_pem_x509_certificate(cert_pem.encode("ascii"), default_backend())
    alg = default_algorithm_for_key(cert.public_key())
    kid = cert_fingerprint(cert_pem)

    headers = {pycose.headers.Algorithm: alg, pycose.headers.KID: kid}
    headers.update(additional_headers or {})
    msg = Sign1Message(phdr=headers, payload=payload)

    key = load_pem_private_key(key_priv_pem.encode("ascii"), None, default_backend())
    if key_type == "ec":
        cose_key = from_cryptography_eckey_obj(key)
    else:
        raise NotImplementedError("unsupported key type")
    msg.key = cose_key

    return msg.encode()


def create_cose_sign1_tbs_digest(
    payload: bytes,
    cert_pem: Pem,
    additional_headers: Optional[dict] = None,
) -> bytes:
    cert = load_pem_x509_certificate(cert_pem.encode("ascii"), default_backend())
    alg = default_algorithm_for_key(cert.public_key())
    kid = cert_fingerprint(cert_pem)

    headers = {pycose.headers.Algorithm: alg, pycose.headers.KID: kid}
    headers.update(additional_headers or {})
    msg = Sign1Message(phdr=headers, payload=payload)
    tbs = cbor2.dumps(["Signature1", msg.phdr_encoded, payload])

    digester = hashes.Hash(cert.signature_hash_algorithm)
    digester.update(tbs)
    return digester.finalize()


_SIGN_DESCRIPTION = """Create and sign a COSE Sign1 message for CCF governance

Note that this tool writes binary COSE Sign1 to standard output.

This is done intentionally to faciliate passing the output directly to curl,
without having to create and read a temporary file on disk. For example:

ccf_cose_sign1 --content ... | curl http://... -H 'Content-Type: application/cose' --data-binary @-
"""


def _sign_parser():
    parser = argparse.ArgumentParser(
        description=_SIGN_DESCRIPTION,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--content",
        help="Path to content file, or '-' for stdin",
        type=str,
        required=True,
    )
    parser.add_argument(
        "--signing-key",
        help="Path to signing key, PEM-encoded",
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
        "--ccf-gov-msg-proposal_id",
        help="ccf.gov.msg.proposal_id protected header",
        type=str,
    )
    return parser


def sign_cli():
    args = _sign_parser().parse_args()

    if args.ccf_gov_msg_type in GOV_MSG_TYPES_WITH_PROPOSAL_ID:
        assert (
            args.ccf_gov_msg_proposal_id is not None
        ), f"Message type {args.ccf_gov_msg_type} requires a proposal id"

    with open(
        args.content, "rb"
    ) if args.content != "-" else sys.stdin.buffer as content_:
        content = content_.read()

    with open(args.signing_key, "r", encoding="utf-8") as signing_key_:
        signing_key = signing_key_.read()

    with open(args.signing_cert, "r", encoding="utf-8") as signing_cert_:
        signing_cert = signing_cert_.read()

    protected_headers = {"ccf.gov.msg.type": args.ccf_gov_msg_type}
    if args.ccf_gov_msg_proposal_id:
        protected_headers["ccf.gov.msg.proposal_id"] = args.ccf_gov_msg_proposal_id

    cose_sign1 = create_cose_sign1(
        content, signing_key, signing_cert, protected_headers
    )
    sys.stdout.buffer.write(cose_sign1)
