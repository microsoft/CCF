# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""
Tests for ccf.merkletree against a from-scratch reference of the merklecpp
semantics: adjacent nodes are paired, a trailing solo node is promoted
unhashed, and the serialised form used in signature transactions is

    >Q num_leaves, >Q num_flushed, leaves[num_flushed:], extras

where extras holds, for each set bit i of num_flushed (least significant
first), the root of the complete subtree of 2**i leaves immediately to the
left of the path to leaf num_flushed.
"""

import struct
from hashlib import sha256

import pytest
from ccf.merkletree import MerkleTree

HASH_SIZE = 32


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
    """Serialise leaves[num_flushed:] of the tree over all of `leaves`."""
    out = struct.pack(">QQ", len(leaves) - num_flushed, num_flushed)
    out += b"".join(leaves[num_flushed:])
    bit = 0
    remaining = num_flushed
    while remaining:
        if remaining & 1:
            start = (num_flushed >> (bit + 1)) << (bit + 1)
            out += reference_root(leaves[start : start + (1 << bit)])
        bit += 1
        remaining >>= 1
    return out


def flushed_hash_count(num_flushed: int) -> int:
    return num_flushed.bit_count()


class TestIncrementalRoot:
    @pytest.mark.parametrize("count", list(range(1, 40)))
    def test_root_matches_reference_after_each_leaf(self, count):
        leaves = [leaf(i) for i in range(count)]
        tree = MerkleTree()
        for n, value in enumerate(leaves, start=1):
            tree.add_leaf(value, do_hash=False)
            assert tree.get_merkle_root() == reference_root(leaves[:n])

    def test_add_leaf_hashes_by_default(self):
        tree = MerkleTree()
        tree.add_leaf(b"transaction bytes")
        assert tree.get_merkle_root() == sha256(b"transaction bytes").digest()


class TestDeserialise:
    @pytest.mark.parametrize(
        "total,num_flushed",
        [(t, f) for t in range(1, 20) for f in range(t)],
    )
    def test_round_trip_and_extension(self, total, num_flushed):
        leaves = [leaf(i) for i in range(total)]
        tree = MerkleTree()
        blob = reference_serialise(leaves, num_flushed)
        end = tree.deserialise(blob)
        assert end == len(blob)
        assert tree.get_merkle_root() == reference_root(leaves)

        # The validator extends the embedded tree with later transactions and
        # compares against the root embedded in the next signature.
        for k in range(5):
            extra = leaf(10_000 + k)
            leaves.append(extra)
            tree.add_leaf(extra, do_hash=False)
            assert tree.get_merkle_root() == reference_root(leaves)

    def test_deserialise_at_offset_consumes_only_the_tree(self):
        leaves = [leaf(i) for i in range(7)]
        blob = reference_serialise(leaves, 5)
        padded = b"\xaa" * 3 + blob + b"\xbb" * 9
        tree = MerkleTree()
        end = tree.deserialise(padded, position=3)
        assert end == 3 + len(blob)
        assert tree.get_merkle_root() == reference_root(leaves)

    @pytest.mark.parametrize("num_flushed", [1, 3, 4, 6, 7])
    def test_rejects_no_retained_leaves(self, num_flushed):
        # merklecpp::Tree::deserialise refuses a serialisation which retains no
        # leaves but claims flushed leaves. The flushed subtree roots are
        # present, so without the check the blob would be accepted and a
        # root unrelated to the full tree could be returned.
        leaves = [leaf(i) for i in range(num_flushed)]
        blob = reference_serialise(leaves, num_flushed)
        assert len(blob) == 16 + HASH_SIZE * flushed_hash_count(num_flushed)
        tree = MerkleTree()
        with pytest.raises(ValueError, match="no retained leaves"):
            tree.deserialise(blob)

    def test_empty_serialised_tree_has_no_root(self):
        tree = MerkleTree()
        assert tree.deserialise(struct.pack(">QQ", 0, 0)) == 16
        assert tree.get_leaf_count() == 0
        with pytest.raises(ValueError, match="Empty tree"):
            tree.get_merkle_root()

    def test_fresh_tree_has_no_root(self):
        with pytest.raises(ValueError, match="Empty tree"):
            MerkleTree().get_merkle_root()

    @pytest.mark.parametrize(
        "cut",
        [0, 8, 15, 16, 16 + HASH_SIZE - 1, 16 + 3 * HASH_SIZE - 1],
        ids=["empty", "half-header", "no-count", "no-hashes", "torn", "no-last"],
    )
    def test_rejects_truncated_buffer(self, cut):
        leaves = [leaf(i) for i in range(4)]
        blob = reference_serialise(leaves, 2)
        assert len(blob) == 16 + 3 * HASH_SIZE
        tree = MerkleTree()
        with pytest.raises(ValueError, match="Buffer too small"):
            tree.deserialise(blob[:cut])
