Architecture
============

.. grid:: 1 2 2 2
    :gutter: 3

    .. grid-item-card:: :fas:`project-diagram` :doc:`consensus/index`

        CCF makes use of a consensus protocol to replicate transactions.

    .. grid-item-card:: :fas:`key` :doc:`cryptography`

        CCF leverages a number of cryptographic techniques and primitives.

    .. grid-item-card:: :fas:`map` :doc:`request_flow`

        Flow of a single request's execution through CCF.

    .. grid-item-card:: :fas:`random` :doc:`threading`

        CCF threading model.

    .. grid-item-card:: :fas:`snowflake` :doc:`merkle_tree`

        Transaction integrity guarantees stem from the use of a Merkle Tree data structure over their history.

    .. grid-item-card:: :fas:`book` :doc:`ledger`

        Transactions are persisted to a ledger for recovery and audit purposes.

    .. grid-item-card:: :fas:`check-double` :doc:`raft_tla`

        TLA+ specifications of CCF.

    .. grid-item-card:: :fas:`paper-plane` :doc:`node_to_node`

        Node to node channel protocol used for consensus and forwarding.

    .. grid-item-card:: :fas:`address-book` :doc:`indexing`

        Indexing system used to speed up historical queries.

    .. grid-item-card:: :fas:`scroll` :doc:`receipts`

        Receipts can be used with the ledger for audit purposes.

    .. grid-item-card:: :fas:`gears` :doc:`tls_internals`

        Internal implementation of TLS communication.

    .. grid-item-card:: :fas:`gears` :doc:`tcp_internals`

        Internal implementation of the TCP host layer.

.. toctree::
    :hidden:
    :maxdepth: 1

    consensus/index
    cryptography
    request_flow
    threading
    merkle_tree
    ledger
    raft_tla
    node_to_node
    indexing
    receipts
    tls_internals
    tcp_internals