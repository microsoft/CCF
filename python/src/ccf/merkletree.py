# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import struct
from hashlib import sha256


class MerkleTree:
    """
    Basic Merkle Tree implementation where leaves comprise of hashed transactions.
    """

    def __init__(self) -> None:
        self.reset_tree()

    def reset_tree(self) -> None:
        """Reset the tree to an empty set of leaves."""
        self._levels: list[list[bytes]] = [[]]
        self._root: bytes | None = None
        self._num_flushed = 0

    def add_leaf(self, values: bytes, do_hash: bool = True) -> None:
        """Append a leaf, hashing its value unless it is already a digest."""
        digest = values
        if do_hash:
            digest = sha256(values).digest()
        self._levels[0].append(digest)
        self._root = None  # Need to recalculate

    @property
    def leaves(self) -> list[bytes]:
        """Return the retained leaf hashes."""
        return self._levels[0]

    def get_leaf(self, index: int) -> bytes:
        return self.leaves[index]

    def get_leaf_count(self) -> int:
        return len(self.leaves)

    def get_merkle_root(self) -> bytes:
        if self._root is None:
            # Same restriction as merklecpp::Tree::root(): a tree with no
            # leaves has no root.
            if self.get_leaf_count() == 0:
                raise ValueError("Empty tree does not have a root")
            # Make tree before getting root if root not already calculated
            self._make_tree()
            assert (
                self._levels is not None
            ), "Unexpected error while getting root. MerkleTree has no levels."
            self._root = self._levels[-1][0]

        return self._root

    @staticmethod
    def _recalculate_level(
        prev_level: list[bytes], level: list[bytes], start: int
    ) -> None:
        """
        Extend level with the hashes of prev_level, in place.
        Reuses already-computed hashes, so the cost is proportional to the
        number of new entries rather than the size of the level.

        Args:
            prev_level: List of hashes from the previous (lower) level
            level: Level to update. level[:start] holds a preserved flushed
                hash, and level[start:] holds previously computed hashes.
            start: Number of preserved entries at the start of level (0 or 1)
        """
        # The last computed entry may be a promoted solo node, so recompute it
        if len(level) > start:
            level.pop()

        # Determine how many pairs are already computed
        done = len(level) - start

        # Handle odd count on input level
        number_of_nodes_on_prev_level = len(prev_level)
        solo_node = None
        if number_of_nodes_on_prev_level % 2 == 1:
            solo_node = prev_level[-1]
            number_of_nodes_on_prev_level -= 1

        # Compute new pairs starting after 'done' existing pairs
        for i in range(done * 2, number_of_nodes_on_prev_level, 2):
            level.append(sha256(prev_level[i] + prev_level[i + 1]).digest())

        if solo_node is not None:
            level.append(solo_node)

    def _make_tree(self) -> None:
        if self.get_leaf_count() == 0:
            return

        # Build tree from leaves. After deserialize, _levels[i] contains:
        # - Flushed hash at [0] if bit i of num_flushed is set
        # - Followed by any previously computed hashes
        # We read from _levels[level_idx] and update _levels[level_idx+1] in
        # place. Copying levels here would make each root computation O(N).
        it = self._num_flushed
        level_idx = 0

        while len(self._levels[level_idx]) > 1 or it != 0:
            # Ensure next level exists
            if level_idx + 1 >= len(self._levels):
                self._levels.append([])

            # Preserve a flushed hash at [0] of the next level, if present
            next_level = self._levels[level_idx + 1]
            start = 1 if (it >> 1) & 0x01 and next_level else 0
            self._recalculate_level(self._levels[level_idx], next_level, start)

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

        # Same restriction as merklecpp::Tree::deserialise(). Without it, the
        # flushed subtree roots would be rebuilt into a tree whose root is not,
        # in general, the root over the flushed leaves.
        if num_leaf_nodes == 0 and self._num_flushed != 0:
            raise ValueError("Serialised tree has no retained leaves")

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
