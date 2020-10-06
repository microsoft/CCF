Ledger
======

The CCF ledger is the persistent replicated append-only record of the transactions that have been executed by the network. It is written by the primary node when a transaction is executed and replicated to all backups which maintain their own duplicated copy. Each node in a network creates and maintains its own local copy of the ledger. Committed entries are always identical, but a node may be more or less up to date, and uncommitted entries may differ.

.. note:: A node writes its ledger to a directory as specified by the ``--ledger-dir`` command line argument.

The entire service state is contained in the ledger (including both governance and application transactions). A single up-to-date copy of the ledger is enough to start a successor service if necessary, following the :doc:`/operators/recovery` procedure.

The ledger contains regular signature transactions (``ccf.signatures`` map) which sign the root of the :term:`Merkle Tree` at the time the signature transaction is emitted.

.. note:: The frequency of the signatures is set by the ``--sig-tx-interval`` and ``--sig-ms-interval`` command line options to ``cchost``.

File Layout
-----------

The ledger directory contains a series of ledger files (or chunks). The size of each ledger file is controlled by the ``--ledger-chunk-bytes`` command line option.

.. note:: When a new node joins from a snapshot (see :doc:`/operators/snapshots`), it is important that subsequent ledger files are the same on all nodes. To do so, a new ledger file is created every time a snapshot is generated, even if the specified size of the file has not yet been reached.

Files containing only committed entries are named ``ledger_$STARTSEQNO-$ENDSEQNO.committed``. These files are closed and immutable, it is safe to replicate them to backup storage. They are identical across nodes, provided ``--ledger-chunk-bytes`` has been set to the same value.

.. warning:: Removing files from a ledger directory may cause a node to crash.

Files that still contain some uncommitted entries will be named ``ledger_$STARTSEQNO-$ENDSEQNO`` or ``ledger_$STARTSEQNO`` for the last one. These files are typically held open by the ``cchost`` process, which may modify their content, or even erase them completely. Uncommitted ledger files may differ arbitrarily across nodes.

It is important to note that while all entries stored in files ending in ``.committed`` are committed, not all committed entries are stored in such a file at any given time. A number of them are typically in the in-progress files, waiting to be flushed to a ``.committed`` file once the size threshold is met.

The listing below is an example of what a ledger directory may look like:

.. code-block:: bash

    $ ./cchost --ledger-dir $LEDGER_DIR ...
    $ cd $LEDGER_DIR
    $ ls -la
    -rw-rw-r-- 1 user user 1.6M Jun 16 14:08 ledger_1-7501.committed
    ...
    -rw-rw-r-- 1 user user 1.1M Jun 16 14:08 ledger_92502-97501.committed
    -rw-rw-r-- 1 user user 553K Jun 16 14:08 ledger_97502

Ledger Encryption
-----------------

Each entry in the ledger corresponds to a transaction committed by the primary node.

When a transaction is committed, each affected ``Store::Map`` is serialised in different security domains (i.e. public or private), based on the policy set when the ``Store::Map`` was created (default is private). A public ``Store::Map`` is serialised and stored in the ledger as plaintext while aprivate ``Store::Map`` is serialised and encrypted before being stored.

Ledger entries are integrity-protected and encrypted using a symmetric key shared by all trusted nodes (see :doc:`/design/cryptography`). This key is kept secure inside each enclave. See :ref:`members/common_member_operations:Rekeying Ledger` for details on how members can rotate the ledger encryption key.

Note that even if a transaction only affects a private ``Store::Map``, unencrypted information such as the version number is always present in the serialised entry. More information about the ledger entry format is available in the :doc:`/developers/kv/kv_serialisation` section.