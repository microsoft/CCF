Ledger and Snapshots Management
===============================

The ledger and snapshots files are written to CCF nodes to disk and should be managed by operators to allow for safe backup of the service state and fast joining and recovery procedures. This section describes how these files are generated and how operators should manage them effectively.

.. note:: See the :doc:`/audit/index` section to read about offline ledger auditability.

Ledger
------

The ledger is the persistent replicated append-only record of the transactions that have been executed by the CCF service. It is written by the primary node when a transaction is executed and replicated to all backups which maintain their own duplicated copy. Each node in a network creates and maintains its own local copy of the ledger. Committed entries are always identical between a majority of nodes (when using :ref:`design/consensus:CFT Consensus Protocol`), but a node may be more or less up to date, and uncommitted entries may differ.

On each node, the ledger is written to disk in a directory specified by the ``--ledger-dir`` command line argument to ``cchost``.

It is also possible to specify an optional read-only ledger directory ``--read-only-ledger-dir`` to ``cchost``. This enables CCF to have access to historical transactions, for example if it joined from a snapshot (see :ref:`operators/snapshots:Historical Transactions`). Note that only committed ledger files can be read from this directory.

TODO: Best practice:
- regularly backup .committed files and copy/mount it to --read-only-ledger-dir when joining/recovering.

File Layout
~~~~~~~~~~~

The ledger growths as transactions mutate CCF's key-value store. The ledger is split into multiple files (or chunks) written by a node in the directory specified by the ``--ledger-dir`` command line argument to ``cchost``. Even though there are multiple ledger files on disk, there is only one unique `logical` ledger file for the lifetime of a CCF service (and across recoveries). The `logical` ledger can be reconstituted by parsing the ledger files in sequence, based on the sequence number included in their file names.

..note:: The size of each ledger file is controlled by the ``--ledger-chunk-bytes`` command line argument to ``cchost``.

Ledger files containing only committed entries are named ``ledger_<start_seqno>-<end_seqno>.committed``, with ``<start_seqno>`` and ``<end_seqno>`` the sequence number of the first and last transaction in the ledger, respectively. These files are closed and immutable, it is safe to replicate them to backup storage. They are identical across nodes, provided ``--ledger-chunk-bytes`` has been set to the same value.

Ledger files that still contain some uncommitted entries will be named ``ledger_<start_seqno>-<end_seqno>`` or ``ledger_<start_seqno>`` for the last one. These files are typically held open by the ``cchost`` process, which may modify their content, or even erase them completely. Uncommitted ledger files may differ arbitrarily across nodes.

.. warning:: Removing files from a ledger directory may cause a node to crash.

It is important to note that while all entries stored in ledger files ending in ``.committed`` are committed, not all committed entries are stored in such a file at any given time. A number of them are typically in the in-progress files, waiting to be flushed to a ``.committed`` file once the size threshold (``--ledger-chunk-bytes``) is met.

The listing below is an example of what a ledger directory may look like:

.. code-block:: bash

    $ cchost --ledger-dir $LEDGER_DIR ...
    $ ls -la $LEDGER_DIR
    -rw-rw-r-- 1 user user 1.6M Jun 16 14:08 ledger_1-7501.committed
    ...
    -rw-rw-r-- 1 user user 1.1M Jun 16 14:08 ledger_92502-97501.committed
    -rw-rw-r-- 1 user user 553K Jun 16 14:08 ledger_97502

Snapshots
---------

When a node is added to an existing service, the entire transaction history is automatically replicated to this new node. Similarly, on recovery, the transaction history since the creation of the service has to be replayed. Depending on the number of historical transactions, adding a node/recovering a service can take some non-negligible period of time, preventing the new node to quickly take part in the consensus and compromising the availability of the service.

To avoid this, it is possible for a new node to be added (or a service to be recovered) from an existing snapshot of the recent CCF state. In this case, only historical transactions between the sequence number at which the snapshot was taken and the latest state will be replicated.

Snapshot Generation
~~~~~~~~~~~~~~~~~~~

Snapshots are generated at regular intervals by the current primary node and stored under the directory specified via the ``--snapshot-dir`` CLI option (defaults to ``snapshots/``). The transaction interval at which snapshots are generated is specified via the ``--snapshot-tx-interval`` CLI option (defaults to no snapshot).

.. note:: Because the generation of a snapshot requires a new ledger chunk to be created (see :ref:`operators/snapshots:File Layout`), all nodes in the network must be started with the same ``--snapshot-tx-interval`` value.

To guarantee that the identity of the primary node that generated the snapshot can be verified offline, the SHA-256 digest of the snapshot (i.e. evidence) is recorded in the ``public:ccf.gov.snapshot_evidence`` table. The snapshot evidence will be signed by the primary node on the next signature transaction (see :ref:`operators/start_network:Signature Interval`).

Committed snapshot files are named ``snapshot_<seqno>.commited_<evidence_seqno>``, with ``<seqno>`` the sequence number of the state of the key-value at which they were generated and ``<evidence_seqno>`` the sequence number at which the snapshot evidence was recorded.

Uncommitted snapshot files, i.e. those whose evidence has not yet been committed, are named ``snapshot_<seqno>``. These files will be ignored by CCF when joining or recovering a service as no evidence can attest of their validity.

Once a snapshot has been generated by the primary, operators can copy or mount the snapshot directory to the new node directory before it is started. On start-up, the new node will automatically resume from the latest committed snapshot file in the ``--snapshot-dir`` directory. If no snapshot file is found, all historical transactions will be replicated to that node.

To validate the snapshot a node joins, the node first replays the transactions in the ledger following the snapshot until the proof that the snapshot was committed by the service to join is found. This process requires operators to copy the ledger suffix to the node's ledger directory. The validation procedure is generally quick and the node will automatically join the service one the snapshot has been validated.

For example, if a node is added using the ``snapshot_1000.committed_1050` snapshot file, operators should copy the ledger files containing the sequence numbers ``1000`` to ``1050`` to the directories specified by ``--ledger-dir`` (or ``--read-only ledger-dir``). In this case, this would involve copying the ledger file ``ledger_1001-1500.committed`` to the joining node's ledger directory.

Historical Transactions
~~~~~~~~~~~~~~~~~~~~~~~

Nodes that started from a snapshot can still process historical queries if the historical ledger (i.e. the ledger files preceding the snapshot) is made accessible to the node via the ``--read-only-ledger-dir`` option to ``cchost``. Although the read-only ledger directory must be specified to the node on start-up, the historical ledger files can be copied to this directory `after` the node is started.
