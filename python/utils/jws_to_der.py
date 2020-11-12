import sys

from pyasn1.type.namedtype import NamedTypes, NamedType
from pyasn1.type.univ import Integer, Sequence
from pyasn1.codec.der.encoder import encode
import base64


file = sys.argv[1]

out_file = f"{file}.der"

with open(file, "rb") as f:
    jws = f.read()


class DERSignature(Sequence):
    componentType = NamedTypes(
        NamedType("r", Integer()),
        NamedType("s", Integer()),
    )


sig = DERSignature()
sig["r"] = int.from_bytes(jws[:48], byteorder="big")
sig["s"] = int.from_bytes(jws[-48:], byteorder="big")
output_buf = encode(sig)

print(base64.b64encode(output_buf).decode())


with open(out_file, "wb") as out:
    out.write(output_buf)

# print(f"DER signature file writen to {out_file}")
