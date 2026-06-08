# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from hashlib import sha256
import math


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
