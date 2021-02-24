# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from hashlib import sha256


class MerkleTree(object):
    """
    Basic Merkle Tree implementation where leaves comprise of hashed transactions.
    """

    def __init__(self):
        self.levels = None
        self.reset_tree()

    def reset_tree(self):
        self.leaves = list()
        self.levels = None

    def add_leaf(self, values: bytes, do_hash=True):
        digest = values
        if do_hash:
            digest = sha256(values).digest()
        self.leaves.append(digest)

    def get_leaf(self, index: int) -> bytes:
        return self.leaves[index]

    def get_leaf_count(self) -> int:
        return len(self.leaves)

    def get_merkle_root(self) -> bytes:
        # Always make tree before getting root
        self._make_tree()
        if self.levels is None:
            raise Exception(
                "Unexpected error while getting root. MerkleTree has no levels."
            )

        return self.levels[0][0]

    def _calculate_next_level(self):
        solo_leaf = None
        # number of leaves on the level
        number_of_leaves_on_current_level = len(self.levels[0])

        if number_of_leaves_on_current_level == 1:
            raise Exception("Merkle Tree should have more than one leaf at every level")

        if (
            number_of_leaves_on_current_level % 2 == 1
        ):  # if odd number of leaves on the level
            # Get the solo leaf (last leaf in-case the leaves are odd numbered)
            solo_leaf = self.levels[0][-1]
            number_of_leaves_on_current_level -= 1

        new_level = []
        for left_node, right_node in zip(
            self.levels[0][0:number_of_leaves_on_current_level:2],
            self.levels[0][1:number_of_leaves_on_current_level:2],
        ):
            new_level.append(sha256(left_node + right_node).digest())
        if solo_leaf is not None:
            new_level.append(solo_leaf)
        self.levels = [
            new_level,
        ] + self.levels  # prepend new level

    def _make_tree(self):
        if self.get_leaf_count() > 0:
            self.levels = [
                self.leaves,
            ]
            while len(self.levels[0]) > 1:
                self._calculate_next_level()
