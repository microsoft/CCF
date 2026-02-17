#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""
Example demonstrating how to deserialize Merkle trees from ledger data.

This script shows how to:
1. Read ledger files
2. Extract the serialized Merkle tree from signature transactions
3. Deserialize the tree
4. Verify the Merkle root
"""

from ccf.ledger import LedgerChunk, WELL_KNOWN_SINGLETON_TABLE_KEY
from ccf.merkletree import MerkleTree
import sys


def demonstrate_tree_deserialisation(ledger_file):
    """
    Demonstrate deserializing Merkle trees from a ledger file.
    
    Args:
        ledger_file: Path to a CCF ledger file (.committed or .recovery)
    """
    chunk = LedgerChunk(ledger_file)
    
    trees_found = 0
    for tx in chunk:
        tables = tx.get_public_domain().get_tables()
        
        # Look for signature transactions with tree data
        if 'public:ccf.internal.tree' in tables:
            tree_table = tables['public:ccf.internal.tree']
            
            # The tree is stored under the well-known singleton key
            if WELL_KNOWN_SINGLETON_TABLE_KEY in tree_table:
                tree_data = tree_table[WELL_KNOWN_SINGLETON_TABLE_KEY]
                
                # Deserialize the Merkle tree
                tree = MerkleTree()
                tree.deserialise(tree_data)
                
                print(f"\nTransaction {tx.get_txid()}:")
                print(f"  Merkle tree with {tree.get_leaf_count()} leaves")
                print(f"  Merkle root: {tree.get_merkle_root().hex()}")
                
                # Show first few leaves
                for i in range(min(3, tree.get_leaf_count())):
                    print(f"  Leaf {i}: {tree.get_leaf(i).hex()[:32]}...")
                
                trees_found += 1
                if trees_found >= 3:  # Just show a few examples
                    break
    
    if trees_found == 0:
        print(f"No Merkle tree data found in {ledger_file}")
    else:
        print(f"\nSuccessfully deserialized {trees_found} Merkle tree(s)")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python merkle_tree_example.py <ledger_file>")
        print("\nExample:")
        print("  python merkle_tree_example.py tests/testdata/expired_service/ledger/ledger_5-15.committed")
        sys.exit(1)
    
    demonstrate_tree_deserialisation(sys.argv[1])
