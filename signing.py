# Scheme A
#
# HTTP
# Headers
# Body
# COSE Sign1
#   Protected Headers
#     URL
#     KID
#   Payload
#     Proposal/Vote


# Scheme B
#
# HTTP
# Headers
#
# KID
# COSE Sign1 ====> Base64 encoded
#   Protected Headers
#     URL
#     KID
#   Payload
#     Proposal/Vote
#
# Body
#   Proposal/Vote

# Scheme C
#
# HTTP
# Headers
# KID
# COSE Sign1 ====> Base64 encoded
#   Protected Headers
#     URL
#     KID
#   Payload
#     Digest(Proposal/Vote)
#
# Body
#   Proposal/Vote


from cose.messages import Sign1Message, CoseMessage
from cose.keys import CoseKey
from cose.headers import Algorithm, KID
from cose.algorithms import Es384
from cose.keys.curves import NIST384p
from cose.keys.keyparam import KpKty, OKPKpD, OKPKpX, KpKeyOps, OKPKpCurve
from cose.keys.keytype import KtyOKP
from cose.keys.keyops import SignOp, VerifyOp

>>> import cose.keys.curves
>>> cose.keys.ec2.EC2Key.generate_key(crv=cose.keys.curves.P384)

msg = Sign1Message(
    phdr = {Algorithm: EdDSA, KID: b'kid2'},
    payload = 'signed message'.encode('utf-8'))

msg
<COSE_Sign1: [{'Algorithm': 'EdDSA', 'KID': b'kid2'}, {}, b'signe' ... (14 B), b'' ... (0 B)]>


cose_key = {
    KpKty: KtyOKP,
    OKPKpCurve: Ed25519,
    KpKeyOps: [SignOp, VerifyOp],
    OKPKpD: unhexlify(b'9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
    OKPKpX: unhexlify(b'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')}

cose_key = CoseKey.from_dict(cose_key)
cose_key
<COSE_Key(OKPKey): {'OKPKpD': "b'\\x9da\\xb1\\x9d\\xef' ... (32 B)", 'OKPKpX': "b'\\xd7Z\\x98\\x01\\x82' ... (32 B)", 'OKPKpCurve': 'Ed25519', 'KpKty': 'KtyOKP', 'KpKeyOps': ['SignOp', 'VerifyOp']}>

msg.key = cose_key
# the encode() function performs the signing automatically
encoded = msg.encode()
hexlify(encoded)
b'd28449a2012704446b696432a04e7369676e6564206d6573736167655840cc87665ffd3fa33d96f3b606fcedeaef839423221872d0bfa196e069a189a607c2284924c3abb80e942466cd300cc5d18fe4e5ea1f3ebdb62ef8419109447d03'

# decode and verify the signature
decoded = CoseMessage.decode(encoded)
decoded
<COSE_Sign1: [{'Algorithm': 'EdDSA', 'KID': b'kid2'}, {}, b'signe' ... (14 B), b'\xcc\x87f_\xfd' ... (64 B)]>

decoded.key = cose_key
decoded.verify_signature()
True

decoded.payload
b'signed message'