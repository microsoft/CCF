Merkle Tree
===========

.. note:: The ``ccf`` Python package provides the ``ledger`` module to easily parse the ledger. More details :doc:`here </audit/python_library>`.

The high-integrity guarantees of CCF are enforced by a single :term:`Merkle Tree` which records the cryptographic hash (leaves) of all transactions that mutate the key-value store. The root of the Merkle Tree is regularly signed by the primary node and the signature is recorded in the ``public:ccf.internal.signatures`` key-value map. Like any other transaction, the signature transaction is also recorded in the ledger (see :doc:`/architecture/ledger` for the transaction format), which allows for offline auditability of the service (for both governance and application history).

The following diagram demonstrates how the integrity of the ledger can be verified: a signature transaction (at ``seqno`` 6) signs the root of the Merkle Tree so far (after the transaction at ``seqno`` 5 has been recorded).

.. image:: ../img/merkle_single_signature.svg
  :width: 1000
  :align: center

Auditors of the CCF ledger can reconstruct the Merkle Tree by walking through the ledger, hashing the transactions recorded in the ledger and appending them to a fresh Merkle Tree. On every signature transaction, the reconstituted root can be compared to the one recorded in the signature transaction. The signature can be verified using the public signing key of the primary node at the time (also recorded in the ledger -- see ``public:ccf.gov.nodes.info`` map). If the signature and root match, the integrity of the ledger so far is guaranteed.

.. note:: The signature transaction also contains the hash of the transactions signed since the last signature. This allows CCF to efficiently issue receipts for historical transactions by only reading the signature transaction that follows the target transaction in the ledger.

To reduce the memory footprint of the Merkle Tree as more transactions are recorded in the ledger, the Merkle Tree is regularly compacted, deleting all historical leaves and intermediate nodes that are no longer required. For example, assuming that the tree is compacted on the next consensus commit, at ``seqno`` 6:

.. image:: ../img/merkle_compact.svg
  :width: 1000
  :align: center

.. note:: In practice, CCF keeps track of a larger historical Merkle Tree in memory so that receipts of recent transactions can be issued efficiently, without having to fetch signature transactions from the ledger.

The compacted Merkle Tree (containing leaves and intermediate nodes to issue receipts for transactions from ``seqno`` 6) is included in the next signature transaction (at ``seqno`` 11):

.. image:: ../img/merkle_two_signatures.svg
  :width: 1000
  :align: center

Serialised Merkle Tree Format
------------------------------

Each signature transaction writes a serialised representation of the compacted Merkle Tree to the ``public:ccf.internal.tree`` key-value map. This serialisation is produced by ``merklecpp.h`` (C++) and can be deserialised by both ``merklecpp.h`` and the ``ccf.merkletree`` Python module. The :doc:`/audit/python_library` uses this format to verify the integrity of the ledger.

The serialised format captures two things:

1. The **leaf hashes** for all transactions that have not been flushed (i.e. the right-hand side of the compacted tree).
2. The **flushed subtree root hashes** along the left edge of the tree, which are needed to reconstruct the full root hash despite the flushed leaves being discarded.

The binary format is big-endian throughout and is structured as follows:

+------------------------------------------+------------------------------------------------------------------------+
| Field Type                               | Description                                                            |
+==========================================+========================================================================+
| uint64_t                                 | Number of leaf hashes (``num_leaf_nodes``)                             |
+------------------------------------------+------------------------------------------------------------------------+
| uint64_t                                 | Number of flushed leaves (``num_flushed``)                             |
+------------------------------------------+------------------------------------------------------------------------+
| **Repeating [0..num_leaf_nodes]**        | Hashes for unflushed leaves                                            |
+---+--------------------------------------+------------------------------------------------------------------------+
|   | SHA-256 hash (32 bytes)              | Hash of an unflushed leaf (e.g. H6, H7, ..., H10 in the diagram)       |
+---+--------------------------------------+------------------------------------------------------------------------+
| **Repeating [0..popcount(num_flushed)]** | Roots of flushed subtrees on the left edge, one per set bit            |
+---+--------------------------------------+------------------------------------------------------------------------+
|   | SHA-256 hash (32 bytes)              | Root hash of a flushed subtree (bit 0 first, then bit 1, etc.)         |
+---+--------------------------------------+------------------------------------------------------------------------+

Flushed Subtree Hashes
~~~~~~~~~~~~~~~~~~~~~~

The ``num_flushed`` field serves double duty: it records both the count of flushed leaves and, through its binary representation, which flushed subtree root hashes are present in the serialisation.

Each set bit ``i`` of ``num_flushed`` indicates a flushed subtree of size :math:`2^i`:

- Bit 0 set: a single flushed leaf hash (at level 0).
- Bit 1 set: a flushed subtree root covering 2 leaves (at level 1).
- Bit 2 set: a flushed subtree root covering 4 leaves (at level 2).
- And so on.

The flushed hashes are serialised in order of ascending level (bit 0 first, then bit 1, etc.), and only for bits that are set.

Example
~~~~~~~

Using the compacted tree from the diagram above, where transactions at ``seqno`` 1--5 have been flushed (``num_flushed = 5 = 0b101``), and ``seqno`` 6--10 remain as leaves:

- ``num_leaf_nodes = 5`` (H6, H7, H8, H9, H10)
- ``num_flushed = 5``
- Leaf hashes: H6, H7, H8, H9, H10
- Bit 0 of ``num_flushed`` is set → flushed hash for 1 leaf: H5
- Bit 1 is not set → no hash
- Bit 2 is set → flushed hash for a subtree of 4 leaves: H1234

During deserialisation, the tree is reconstructed level by level. At each level, if the corresponding bit in ``num_flushed`` is set, the flushed subtree root hash is inserted at the left of that level before pairing nodes upward. This restores the same root hash as the original (uncompacted) tree.