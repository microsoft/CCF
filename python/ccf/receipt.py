# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from hashlib import sha256
from typing import List


def root(leaf: str, proof: List[dict]):
    current = bytes.fromhex(leaf)
    for n in proof:
        if "left" in n:
            current = sha256(bytes.fromhex(n["left"]) + current).digest()
        else:
            current = sha256(current + bytes.fromhex(n["right"])).digest()
    return current.hex().upper()
