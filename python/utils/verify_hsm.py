from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.hazmat.primitives.asymmetric import padding, ec, utils
from cryptography.hazmat.primitives import hashes

import sys

if __name__ == "__main__":
    private_key_pem_path = sys.argv[1]
    signature_path = sys.argv[2]
    signed_hash_path = sys.argv[3]

    with open(private_key_pem_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), None, default_backend())

    with open(signature_path, "rb") as f:
        signature = f.read()

    with open(signed_hash_path, "rb") as f:
        digest = f.read()

    print(f"Signature: {signature}")
    print(f"Digest: {digest}")

    signature_algorithm = ec.ECDSA(utils.Prehashed(hashes.SHA384()))

    public_key = private_key.public_key()

    private_key.sign()
    public_key.verify(signature, digest, signature_algorithm)
