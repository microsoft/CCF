# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import sys

from pyasn1.type.namedtype import NamedTypes, NamedType
from pyasn1.type.univ import Integer, Sequence
from pyasn1.codec.der.encoder import encode
import base64


class DERSignature(Sequence):
    componentType = NamedTypes(
        NamedType("r", Integer()),
        NamedType("s", Integer()),
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Error: base64url signature should be specified as first argument")
        sys.exit(1)

    jws_raw = base64.urlsafe_b64decode(sys.argv[1])
    jws_raw_len = len(jws_raw)

    sig = DERSignature()
    sig["r"] = int.from_bytes(jws_raw[: int(jws_raw_len / 2)], byteorder="big")
    sig["s"] = int.from_bytes(jws_raw[-int(jws_raw_len / 2) :], byteorder="big")
    output_buf = encode(sig)

    print(base64.b64encode(output_buf).decode())
