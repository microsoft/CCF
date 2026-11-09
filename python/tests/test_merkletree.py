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

import random
import struct
import tracemalloc
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


@pytest.mark.parametrize("num_flushed", [0, 1, 6, 13])
def test_root_updates_levels_in_place(num_flushed: int):
    # Recomputing the root after adding leaves must extend the existing levels
    # rather than copy them, otherwise each root costs O(N) and validating a
    # ledger with frequent signatures becomes quadratic.
    leaves = [leaf(i) for i in range(100)]
    tree = MerkleTree()
    tree.deserialise(reference_serialise(leaves, num_flushed))
    assert tree.get_merkle_root() == reference_root(leaves)
    levels = list(tree._levels)
    for k in range(10):
        leaves.append(leaf(10_000 + k))
        tree.add_leaf(leaves[-1], do_hash=False)
        assert tree.get_merkle_root() == reference_root(leaves)
        for before, after in zip(levels, tree._levels):
            assert after is before


@pytest.mark.parametrize("num_flushed", [0, 1, 4097])
def test_roots_at_random_points(num_flushed: int):
    rng = random.Random(num_flushed)
    leaves = [leaf(i) for i in range(num_flushed + 1)]
    tree = MerkleTree()
    tree.deserialise(reference_serialise(leaves, num_flushed))
    for k in range(2_000):
        leaves.append(leaf(10_000 + k))
        tree.add_leaf(leaves[-1], do_hash=False)
        if rng.random() < 0.05:
            assert tree.get_merkle_root() == reference_root(leaves)
    assert tree.get_merkle_root() == reference_root(leaves)


@pytest.mark.parametrize("cached_root", [False, True])
@pytest.mark.parametrize("total", [1, 2, 3, 7, 8, 9, 31, 32, 33, 256, 257])
def test_flush_contract(total: int, cached_root: bool):
    leaves = [leaf(i) for i in range(total)]
    tree = MerkleTree()
    for digest in leaves:
        tree.add_leaf(digest, do_hash=False)
    expected_root = reference_root(leaves)
    if cached_root:
        assert tree.get_merkle_root() == expected_root
    for index in sorted({total // 2, total - 1}):
        tree.flush(index)
        assert tree.get_leaf_count() == total
        assert tree.leaves == leaves[index:]
        for i in range(index):
            with pytest.raises(IndexError):
                tree.get_leaf(i)
        for i in range(index, total):
            assert tree.get_leaf(i) == leaves[i]
        assert tree.get_merkle_root() == expected_root
    for k in range(5):
        leaves.append(leaf(10_000 + k))
        tree.add_leaf(leaves[-1], do_hash=False)
        assert tree.get_merkle_root() == reference_root(leaves)


@pytest.mark.parametrize("num_flushed", [0, 1, 6, 13, 129])
def test_mixed_flush_append_and_deserialise(num_flushed: int):
    rng = random.Random(num_flushed)
    leaves = [leaf(i) for i in range(num_flushed + 1)]
    tree = MerkleTree()
    tree.deserialise(reference_serialise(leaves, num_flushed))
    first_retained = num_flushed
    for step in range(20):
        for i in range(rng.randrange(1, 17)):
            value = (10_000 + step * 16 + i).to_bytes(8, "little")
            do_hash = rng.choice([False, True])
            if not do_hash:
                value = sha256(value).digest()
            tree.add_leaf(value, do_hash=do_hash)
            leaves.append(sha256(value).digest() if do_hash else value)
        if rng.choice([False, True]):
            assert tree.get_merkle_root() == reference_root(leaves)
        index = rng.randrange(len(leaves))
        tree.flush(index)
        first_retained = max(first_retained, index)
        assert tree.leaves == leaves[first_retained:]
        assert tree.get_leaf_count() == len(leaves)
        assert tree.get_leaf(first_retained) == leaves[first_retained]
        assert tree.get_leaf(len(leaves) - 1) == leaves[-1]
        if first_retained:
            with pytest.raises(IndexError):
                tree.get_leaf(first_retained - 1)
        assert tree.get_merkle_root() == reference_root(leaves)
        if step % 5 == 0:
            blob = reference_serialise(leaves, first_retained)
            assert tree.deserialise(blob) == len(blob)


def test_flush_bounds_and_reset():
    tree = MerkleTree()
    tree.flush(0)  # Like C++, flushing to min_index is a no-op, even when empty.
    with pytest.raises(IndexError):
        tree.flush(1)
    leaves = [leaf(i) for i in range(8)]
    for digest in leaves:
        tree.add_leaf(digest, do_hash=False)
    tree.flush(5)
    for index in range(6):
        tree.flush(index)
        assert tree.leaves == leaves[5:]
        assert tree.get_leaf_count() == len(leaves)
        assert tree.get_merkle_root() == reference_root(leaves)
    for index in [-1, 8, 100]:
        with pytest.raises(IndexError):
            tree.flush(index)
        with pytest.raises(IndexError):
            tree.get_leaf(index)
        assert tree.leaves == leaves[5:]
        assert tree.get_merkle_root() == reference_root(leaves)
    tree.reset_tree()
    tree.add_leaf(leaves[0], do_hash=False)
    assert tree.get_leaf_count() == 1
    assert tree.get_leaf(0) == leaves[0]
    assert tree.get_merkle_root() == leaves[0]


def test_periodic_flush_releases_allocations():
    def retained_memory(flush: bool) -> tuple[int, bytes]:
        tracemalloc.start()
        try:
            before, _ = tracemalloc.get_traced_memory()
            tree = MerkleTree()
            for i in range(4_096):
                tree.add_leaf(leaf(i), do_hash=False)
                if i % 31 == 0:
                    tree.get_merkle_root()
                    if flush:
                        tree.flush(i)
            root = tree.get_merkle_root()
            after, _ = tracemalloc.get_traced_memory()
            return after - before, root
        finally:
            tracemalloc.stop()

    unflushed_bytes, unflushed_root = retained_memory(flush=False)
    flushed_bytes, flushed_root = retained_memory(flush=True)
    assert flushed_root == unflushed_root
    # A generous relative bound catches retained historical hashes without
    # specifying how a tree stores the remaining nodes.
    assert flushed_bytes < unflushed_bytes // 10


@pytest.mark.parametrize("size", [0, 31, 33, 64])
def test_unhashed_leaf_must_be_digest(size: int):
    tree = MerkleTree()
    tree.add_leaf(leaf(0), do_hash=False)
    root = tree.get_merkle_root()
    with pytest.raises(ValueError, match="Leaf digest must be 32 bytes"):
        tree.add_leaf(bytes(size), do_hash=False)
    assert tree.get_leaf_count() == 1
    assert tree.get_merkle_root() == root
    tree.add_leaf(bytes(size))
    assert tree.get_leaf(1) == sha256(bytes(size)).digest()
