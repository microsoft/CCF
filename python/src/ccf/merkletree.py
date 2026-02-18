# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from hashlib import sha256
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
        self._num_flushed = 0

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
            self._root = self._levels[-1][0]

        return self._root

    def _recalculate_level(self, prev_level, current_level):
        """
        Compute the next level of hashes from the previous level.
        Reuses already-computed hashes where possible.

        Args:
            prev_level: List of hashes from the previous (lower) level
            current_level: List of already-computed hashes at this level

        Returns:
            Updated list of computed hashes for this level
        """
        # Handle solo leaf: if last entry was a promoted solo, pop it for recalc
        if current_level:
            current_level.pop(-1)

        # Determine how many pairs are already computed
        done = len(current_level)

        # Handle odd count on input level
        number_of_leaves_on_prev_level = len(prev_level)
        solo_leaf = None
        if number_of_leaves_on_prev_level % 2 == 1:
            solo_leaf = prev_level[-1]
            number_of_leaves_on_prev_level -= 1

        # Compute new pairs starting after 'done' existing pairs
        for left_node, right_node in zip(
            prev_level[done * 2 : number_of_leaves_on_prev_level : 2],
            prev_level[done * 2 + 1 : number_of_leaves_on_prev_level : 2],
        ):
            current_level.append(sha256(left_node + right_node).digest())

        if solo_leaf is not None:
            current_level.append(solo_leaf)

        return current_level

    def _make_tree(self):
        if self.get_leaf_count() == 0:
            return

        # Build tree from leaves. After deserialize, _levels[i] contains:
        # - Flushed hash at [0] if bit i of num_flushed is set
        # - Followed by any previously computed hashes
        # We read from _levels[level_idx] and write computed hashes to _levels[level_idx+1].
        it = self._num_flushed
        level_idx = 0

        while len(self._levels[level_idx]) > 1 or it != 0:
            prev_level = self._levels[level_idx]

            # Ensure next level exists
            if level_idx + 1 >= len(self._levels):
                self._levels.append([])

            # Check if next level has a flushed hash at [0] that we must preserve
            next_level = self._levels[level_idx + 1]
            next_has_flushed = (it >> 1) & 0x01 and next_level

            # Compute next level, reusing hashes after the flushed one
            skip = 1 if next_has_flushed else 0
            computed = self._recalculate_level(prev_level, next_level[skip:])

            # Store result, preserving flushed hash at [0] if present
            if next_has_flushed:
                self._levels[level_idx + 1] = [next_level[0]] + computed
            else:
                self._levels[level_idx + 1] = computed

            it >>= 1
            level_idx += 1

    def deserialise(self, buffer: bytes, position: int = 0) -> int:
        """
        Deserialise a compact merkle tree representation.

        Format (big-endian):
          [uint64_t] num_leaf_nodes - Count of leaf nodes in this serialisation
          [uint64_t] num_flushed - Count of flushed (pruned) leaves
          [hash...] leaf_hashes - Hash data for leaf nodes (32 bytes each)
          [hash...] flushed_hashes - Roots of flushed subtrees on the left edge

        Args:
            buffer: The byte buffer containing the serialised tree
            position: Starting position in the buffer (default: 0)

        Returns:
            The new position in the buffer after deserialisation
        """
        HASH_SIZE = 32  # SHA-256 hash size

        # Helper function to read bytes and advance position
        def read_bytes(pos: int, size: int) -> tuple[bytes, int]:
            """Read size bytes from buffer at pos, return (data, new_pos)"""
            if len(buffer) < pos + size:
                raise ValueError(
                    f"Buffer too small: need {pos + size} bytes, have {len(buffer)}"
                )
            return buffer[pos : pos + size], pos + size

        # Reset the tree
        self.reset_tree()

        # Parse header - big-endian uint64_t values
        uint64_data, position = read_bytes(position, 8)
        num_leaf_nodes = struct.unpack(">Q", uint64_data)[0]

        uint64_data, position = read_bytes(position, 8)
        self._num_flushed = struct.unpack(">Q", uint64_data)[0]

        # Read leaf hashes into _levels[0]
        for _ in range(num_leaf_nodes):
            leaf_hash, position = read_bytes(position, HASH_SIZE)
            self._levels[0].append(leaf_hash)

        # Read flushed subtree hashes into their conceptual levels.
        # Bit i of num_flushed indicates a flushed subtree of size 2^i,
        # whose root is at level i (for i>0) or a single leaf at level 0 (i=0).
        it = self._num_flushed
        level = 0

        while it != 0:
            if it & 0x01:
                flushed_hash, position = read_bytes(position, HASH_SIZE)
                if level == 0:
                    # Flushed leaf - insert at beginning of level 0
                    self._levels[0].insert(0, flushed_hash)
                else:
                    # Ensure level exists
                    while len(self._levels) <= level:
                        self._levels.append([])
                    # Store flushed hash at its conceptual level
                    self._levels[level] = [flushed_hash]
            level += 1
            it >>= 1

        return position
