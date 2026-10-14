# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""
Tests for ccf.merkletree against a from-scratch reference of the merklecpp
semantics: adjacent nodes are paired and a trailing solo node is promoted
unhashed. A partial serialisation holds >Q num_leaves, >Q num_flushed, the
retained leaves, then for each set bit i of num_flushed (least significant
first) the root of the complete subtree of 2**i leaves to the left of the
path to leaf num_flushed.
"""

import struct
from hashlib import sha256

import pytest
from ccf.merkletree import MerkleTree


def leaf(seed: int) -> bytes:
    return sha256(seed.to_bytes(8, "little")).digest()


def reference_root(nodes: list[bytes]) -> bytes:
    nodes = list(nodes)
    while len(nodes) > 1:
        paired = [
            sha256(nodes[i] + nodes[i + 1]).digest()
            for i in range(0, len(nodes) - 1, 2)
        ]
        if len(nodes) % 2:
            paired.append(nodes[-1])
        nodes = paired
    return nodes[0]


def reference_serialise(leaves: list[bytes], num_flushed: int) -> bytes:
    out = struct.pack(">QQ", len(leaves) - num_flushed, num_flushed)
    out += b"".join(leaves[num_flushed:])
    for bit in range(num_flushed.bit_length()):
        if (num_flushed >> bit) & 1:
            start = (num_flushed >> (bit + 1)) << (bit + 1)
            out += reference_root(leaves[start : start + (1 << bit)])
    return out


@pytest.mark.parametrize(
    ("total", "num_flushed"), [(t, f) for t in range(1, 17) for f in range(t)]
)
def test_round_trip_and_extension(total: int, num_flushed: int):
    leaves = [leaf(i) for i in range(total)]
    blob = reference_serialise(leaves, num_flushed)
    tree = MerkleTree()
    assert tree.deserialise(blob) == len(blob)
    assert tree.get_merkle_root() == reference_root(leaves)
    # The validator extends the embedded tree with later transactions
    for k in range(5):
        leaves.append(leaf(10_000 + k))
        tree.add_leaf(leaves[-1], do_hash=False)
        assert tree.get_merkle_root() == reference_root(leaves)


@pytest.mark.parametrize("num_flushed", [1, 4, 6])
def test_no_retained_leaves_rejected(num_flushed: int):
    # As merklecpp::Tree::deserialise does. The flushed subtree roots are all
    # present, so this is not a truncation error.
    blob = reference_serialise([leaf(i) for i in range(num_flushed)], num_flushed)
    with pytest.raises(ValueError, match="no retained leaves"):
        MerkleTree().deserialise(blob)


def test_empty_tree_has_no_root():
    tree = MerkleTree()
    assert tree.deserialise(struct.pack(">QQ", 0, 0)) == 16
    with pytest.raises(ValueError, match="Empty tree"):
        tree.get_merkle_root()
