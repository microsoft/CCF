Architecture
============

.. panels::

    :fa:`book` :doc:`consensus/index`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Different consensus protocols can be used to replicate state in a CCF network.

    ---

    :fa:`key` :doc:`cryptography`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    CCF leverages a number of cryptographic techniques and primitives.

    ---

    :fa:`stream` :doc:`threading`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    CCF threading model.

    ---

    :fa:`project-diagram` :doc:`merkle_tree`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Transaction integrity guarantees stem from the use of a Merkle Tree data structure over their history.

    ---

    :fa:`book` :doc:`ledger`
    ^^^^^^^^^^^^^^^^^^^^^^^^

    Transactions are persisted to a ledger for recovery and audit purposes.

    ---

    :fa:`book` :doc:`raft_tla`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^

    A TLA+ model of Raft as modified when implemented in CCF.

    ---

.. toctree::
    :hidden:
    :maxdepth: 1

    consensus/index
    cryptography
    threading
    merkle_tree
    ledger
    raft_tla