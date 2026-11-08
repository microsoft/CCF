Architecture
============

.. grid:: 1 2 2 2
    :gutter: 3

    .. grid-item-card:: :fas:`project-diagram` :doc:`consensus/index`

        Understand how CCF replicates transactions using consensus.

    .. grid-item-card:: :fas:`key` :doc:`cryptography`

        Explore CCF cryptographic techniques and primitives.

    .. grid-item-card:: :fas:`map` :doc:`request_flow`

        Follow a request through CCF.

    .. grid-item-card:: :fas:`random` :doc:`threading`

        Understand the CCF threading model.

    .. grid-item-card:: :fas:`snowflake` :doc:`merkle_tree`

        Understand how Merkle trees protect transaction integrity.

    .. grid-item-card:: :fas:`book` :doc:`ledger`

        Understand ledger persistence for recovery and auditing.

    .. grid-item-card:: :fas:`paper-plane` :doc:`node_to_node`

        Understand the node-to-node channel protocol used for consensus and forwarding.

    .. grid-item-card:: :fas:`address-book` :doc:`indexing`

        Use indexing to speed up historical queries.

    .. grid-item-card:: :fas:`scroll` :doc:`receipts`

        Understand how receipts support ledger auditing.

    .. grid-item-card:: :fas:`cogs` :doc:`tls_internals`

        Explore the internal implementation of TLS communication.

    .. grid-item-card:: :fas:`cogs` :doc:`tcp_internals`

        Explore the internal implementation of the TCP host layer.

.. toctree::
    :hidden:
    :maxdepth: 1

    consensus/index
    cryptography
    request_flow
    threading
    merkle_tree
    ledger
    node_to_node
    indexing
    receipts
    tls_internals
    tcp_internals