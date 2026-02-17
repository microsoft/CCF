# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from hashlib import sha256
import math
import struct


class MerkleTree(object):
    """
    Basic Merkle Tree implementation where leaves comprise of hashed transactions.
    """

    def __init__(self):
        self.reset_tree()

    def reset_tree(self):
        self._levels = [[]]
        self._root = None

    def add_leaf(self, values: bytes, do_hash=True):
        digest = values
        if do_hash:
            digest = sha256(values).digest()
        self._levels[0].append(digest)
        self._root = None  # Need to recalculate

    @property
    def leaves(self):
        return self._levels[0]

    def get_leaf(self, index: int) -> bytes:
        return self.leaves[index]

    def get_leaf_count(self) -> int:
        return len(self.leaves)

    def get_merkle_root(self) -> bytes:
        if self._root is None:
            # Make tree before getting root if root not already calculated
            self._make_tree()
            assert (
                self._levels is not None
            ), "Unexpected error while getting root. MerkleTree has no levels."
            if self._levels and self._levels[-1]:
                self._root = self._levels[-1][0]

        return self._root

    def _recalculate_level(self, level):
        assert len(self._levels) > level - 1
        prev_level = self._levels[level - 1]
        number_of_leaves_on_prev_level = len(prev_level)

        assert (
            number_of_leaves_on_prev_level > 1
        ), "Merkle Tree should have more than one leaf at every level"

        solo_leaf = None

        if (
            number_of_leaves_on_prev_level % 2 == 1
        ):  # if odd number of leaves on the level
            # Get the solo leaf (last leaf in-case the leaves are odd numbered)
            solo_leaf = prev_level[-1]
            number_of_leaves_on_prev_level -= 1

        if not len(self._levels) > level:
            self._levels.append([])

        # Reuse existing level as much as possible
        current_level = self._levels[level]

        # Since we may have copied a solo-leaf to the rightmost node last time, pop and re-calculate it
        if len(current_level):
            current_level.pop(-1)

        done = len(current_level)

        for left_node, right_node in zip(
            prev_level[done * 2 : number_of_leaves_on_prev_level : 2],
            prev_level[done * 2 + 1 : number_of_leaves_on_prev_level : 2],
        ):
            current_level.append(sha256(left_node + right_node).digest())
        if solo_leaf is not None:
            current_level.append(solo_leaf)

    def _make_tree(self):
        if self.get_leaf_count() > 0:
            num_levels = 1 + math.ceil(math.log(self.get_leaf_count(), 2))
            for level in range(1, num_levels):
                self._recalculate_level(level)

    def deserialise(self, buffer: bytes, position: int = 0) -> int:
        """
        Deserialise a compact merkle tree representation.
        
        Format (big-endian):
          [uint64_t] num_leaf_nodes - Total leaf nodes count
          [uint64_t] num_flushed - Bitmask indicating flushed nodes
          [hash...] leaf_hashes - Hash data for all leaf nodes (32 bytes each)
          [extra_hashes...] - Extra nodes on the left edge of tree (32 bytes each)
        
        Args:
            buffer: The byte buffer containing the serialised tree
            position: Starting position in the buffer (default: 0)
            
        Returns:
            The new position in the buffer after deserialisation
        """
        HASH_SIZE = 32  # SHA-256 hash size
        
        # Reset the tree
        self.reset_tree()
        
        # Parse header - big-endian uint64_t values
        if len(buffer) < position + 16:
            raise ValueError("Buffer too small for tree header")
        
        num_leaf_nodes = struct.unpack('>Q', buffer[position:position + 8])[0]
        position += 8
        num_flushed = struct.unpack('>Q', buffer[position:position + 8])[0]
        position += 8
        
        # Read leaf hashes
        if len(buffer) < position + num_leaf_nodes * HASH_SIZE:
            raise ValueError("Buffer too small for leaf hashes")
        
        leaf_nodes = []
        for i in range(num_leaf_nodes):
            leaf_hash = buffer[position:position + HASH_SIZE]
            position += HASH_SIZE
            leaf_nodes.append(leaf_hash)
        
        # Build tree levels bottom-up, similar to C++ implementation
        # Start with leaf nodes as the first level
        level = leaf_nodes[:]
        next_level = []
        it = num_flushed
        level_no = 0
        
        while it != 0 or len(level) > 1:
            # Restore extra hashes on the left edge of the tree
            if it & 0x01:
                if len(buffer) < position + HASH_SIZE:
                    raise ValueError("Buffer too small for extra hash")
                extra_hash = buffer[position:position + HASH_SIZE]
                position += HASH_SIZE
                # Insert at the beginning of the level
                level.insert(0, extra_hash)
            
            # Rebuild the level by pairing nodes
            next_level = []
            for i in range(0, len(level), 2):
                if i + 1 >= len(level):
                    # Odd node - propagate to next level
                    next_level.append(level[i])
                else:
                    # Pair of nodes - hash them together
                    combined_hash = sha256(level[i] + level[i + 1]).digest()
                    next_level.append(combined_hash)
            
            level = next_level
            it >>= 1
            level_no += 1
        
        # Store the reconstructed tree structure
        # The tree should end with 0 or 1 node (the root)
        if len(level) == 1:
            self._root = level[0]
            # Reconstruct _levels for compatibility with the rest of the class
            # Start with the original leaves
            self._levels = [leaf_nodes[:]]
        elif len(level) == 0 and num_leaf_nodes == 0:
            # Empty tree
            self._levels = [[]]
            self._root = None
        else:
            raise ValueError(f"Invalid tree state: {len(level)} nodes at root level")
        
        return position
