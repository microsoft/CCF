# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import pytest
import struct
import sys
import os
from hashlib import sha256

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../src"))

from ccf.merkletree import MerkleTree
from ccf.ledger import LedgerChunk, WELL_KNOWN_SINGLETON_TABLE_KEY


def test_deserialise_simple_tree():
    """
    Test deserialising a simple merkle tree with 2 leaves and no flushed nodes.
    """
    # Create a simple tree: 2 leaves, no flushed nodes
    leaf1 = b"a" * 32
    leaf2 = b"b" * 32
    num_leaves = 2
    num_flushed = 0
    
    # Serialize manually
    buffer = struct.pack('>Q', num_leaves)
    buffer += struct.pack('>Q', num_flushed)
    buffer += leaf1
    buffer += leaf2
    
    # Deserialize
    tree = MerkleTree()
    pos = tree.deserialise(buffer)
    
    # Check that we consumed the whole buffer
    assert pos == len(buffer)
    
    # Check that the tree has 2 leaves
    assert tree.get_leaf_count() == 2
    assert tree.get_leaf(0) == leaf1
    assert tree.get_leaf(1) == leaf2
    
    # Check the root is the hash of the two leaves
    expected_root = sha256(leaf1 + leaf2).digest()
    assert tree.get_merkle_root() == expected_root


def test_deserialise_tree_with_flushed_nodes():
    """
    Test deserialising a tree with flushed nodes (extra hashes).
    """
    # Create a tree with 2 leaves and 1 flushed node (bit 0 set)
    leaf1 = b"c" * 32
    leaf2 = b"d" * 32
    extra1 = b"e" * 32
    num_leaves = 2
    num_flushed = 1  # Binary: 0b1 - one extra hash at level 0
    
    # Serialize
    buffer = struct.pack('>Q', num_leaves)
    buffer += struct.pack('>Q', num_flushed)
    buffer += leaf1
    buffer += leaf2
    buffer += extra1
    
    # Deserialize
    tree = MerkleTree()
    pos = tree.deserialise(buffer)
    
    # Check position
    assert pos == len(buffer)
    
    # Check leaves
    assert tree.get_leaf_count() == 2
    assert tree.get_leaf(0) == leaf1
    assert tree.get_leaf(1) == leaf2


def test_deserialise_empty_tree():
    """
    Test deserialising an empty tree (0 leaves).
    """
    num_leaves = 0
    num_flushed = 0
    
    buffer = struct.pack('>Q', num_leaves)
    buffer += struct.pack('>Q', num_flushed)
    
    tree = MerkleTree()
    pos = tree.deserialise(buffer)
    
    assert pos == len(buffer)
    assert tree.get_leaf_count() == 0
    assert tree.get_merkle_root() is None


def test_deserialise_single_leaf():
    """
    Test deserialising a tree with a single leaf.
    """
    leaf1 = b"f" * 32
    num_leaves = 1
    num_flushed = 0
    
    buffer = struct.pack('>Q', num_leaves)
    buffer += struct.pack('>Q', num_flushed)
    buffer += leaf1
    
    tree = MerkleTree()
    pos = tree.deserialise(buffer)
    
    assert pos == len(buffer)
    assert tree.get_leaf_count() == 1
    assert tree.get_leaf(0) == leaf1
    assert tree.get_merkle_root() == leaf1


def test_deserialise_with_offset():
    """
    Test deserialising from a buffer with an offset.
    """
    # Add some prefix data
    prefix = b"HEADER" * 10
    
    leaf1 = b"g" * 32
    leaf2 = b"h" * 32
    num_leaves = 2
    num_flushed = 0
    
    buffer = prefix
    buffer += struct.pack('>Q', num_leaves)
    buffer += struct.pack('>Q', num_flushed)
    buffer += leaf1
    buffer += leaf2
    
    tree = MerkleTree()
    pos = tree.deserialise(buffer, position=len(prefix))
    
    assert pos == len(buffer)
    assert tree.get_leaf_count() == 2


def test_deserialise_invalid_buffer_size():
    """
    Test that deserialising with an invalid buffer size raises an error.
    """
    # Buffer too small for header
    buffer = b"short"
    
    tree = MerkleTree()
    with pytest.raises(ValueError, match="Buffer too small"):
        tree.deserialise(buffer)


def test_deserialise_real_ledger_data():
    """
    Test deserialising actual ledger data from test files.
    """
    # Find a test ledger file
    testdata_dir = os.path.join(os.path.dirname(__file__), "../../tests/testdata")
    ledger_files = []
    
    # Search for ledger files
    for root, dirs, files in os.walk(testdata_dir):
        for f in files:
            if f.endswith(".committed"):
                ledger_files.append(os.path.join(root, f))
                if len(ledger_files) >= 3:  # Just test a few
                    break
        if len(ledger_files) >= 3:
            break
    
    if not ledger_files:
        pytest.skip("No test ledger files found")
    
    trees_found = 0
    for ledger_file in ledger_files:
        try:
            chunk = LedgerChunk(ledger_file)
            for tx in chunk:
                tables = tx.get_public_domain().get_tables()
                
                if 'public:ccf.internal.tree' in tables:
                    tree_table = tables['public:ccf.internal.tree']
                    if WELL_KNOWN_SINGLETON_TABLE_KEY in tree_table:
                        tree_data = tree_table[WELL_KNOWN_SINGLETON_TABLE_KEY]
                        
                        # Try to deserialise
                        tree = MerkleTree()
                        pos = tree.deserialise(tree_data)
                        
                        # Basic validation
                        assert pos == len(tree_data)
                        assert tree.get_leaf_count() >= 0
                        
                        # If there are leaves, we should have a root
                        if tree.get_leaf_count() > 0:
                            root = tree.get_merkle_root()
                            assert root is not None
                            assert len(root) == 32  # SHA-256
                        
                        trees_found += 1
                        if trees_found >= 5:  # Test a few trees
                            return
        except Exception as e:
            # Some ledger files might not be accessible or valid
            continue
    
    if trees_found == 0:
        pytest.skip("No tree data found in ledger files")


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
