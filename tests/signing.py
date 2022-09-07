# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

import base64

import cose.headers
from cose.keys.ec2 import EC2Key
from cose.keys.curves import P256, P384, P521
from cose.keys.keyparam import EC2KpCurve, EC2KpX, EC2KpY, EC2KpD
from cose.messages import Sign1Message
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

Pem = str

def from_cryptography_eckey_obj(ext_key) -> EC2Key:
    """
    Returns an initialized COSE Key object of type EC2Key.
    :param ext_key: Python cryptography key.
    :return: an initialized EC key
    """
    if hasattr(ext_key, 'private_numbers'):
        priv_nums = ext_key.private_numbers()
        pub_nums = priv_nums.public_numbers
    else:
        priv_nums = None
        pub_nums = ext_key.public_numbers()

    if pub_nums.curve.name == 'secp256r1':
        curve = P256
    elif pub_nums.curve.name == 'secp384r1':
        curve = P384
    elif pub_nums.curve.name == 'secp521r1':
        curve = P521
    else:
        raise NotImplementedError("unsupported curve")

    cose_key = {}
    if pub_nums:
        cose_key.update({
            EC2KpCurve: curve,
            EC2KpX: pub_nums.x.to_bytes(curve.size, 'big'),
            EC2KpY: pub_nums.y.to_bytes(curve.size, 'big'),
        })
    if priv_nums:
        cose_key.update({
            EC2KpD: priv_nums.private_value.to_bytes(curve.size, 'big'),
        })
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
        raise NotImplementedError('unsupported key type')

def get_priv_key_type(priv_pem: str) -> str:
    key = load_pem_private_key(priv_pem.encode("ascii"), None, default_backend())
    if isinstance(key, EllipticCurvePrivateKey):
        return 'ec'
    raise NotImplementedError('unsupported key type')

    # if kid is None:
    #     kid = hashlib.sha256(der).hexdigest()
    # if alg is None:
    #     alg = default_algorithm_for_key(pub_key)

def create_cose_sign1(payload: bytes, key_priv_pem: Pem, headers: dict) -> bytes:
    key_type = get_priv_key_type(key_priv_pem)

    headers[cose.headers.Algorithm] = headers.pop('alg')
    headers[cose.headers.KID] = headers.pop('kid').encode('utf-8')
    headers[cose.headers.ContentType] = headers.pop('cty')

    msg = Sign1Message(
        phdr=headers,
        payload=payload)
    
    key = load_pem_private_key(key_priv_pem.encode("ascii"), None, default_backend())
    if key_type == 'ec':
        cose_key = from_cryptography_eckey_obj(key)
    else:
        raise NotImplementedError('unsupported key type')
    msg.key = cose_key

    return msg.encode(tag=True)

if __name__ == "__main__":
    pass
    # create_cose_sign1("hello")