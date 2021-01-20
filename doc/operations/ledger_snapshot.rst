Ledger and Snapshots
====================

The ledger and snapshot files written by CCF nodes to disk should be managed by operators to allow for safe backup of the service and application state as well as fast join and recovery procedures. This section describes how these files are generated and how operators should manage them effectively.

.. note:: See the :doc:`/audit/index` section to read about offline ledger auditability.

Ledger
------

The ledger is the persistent replicated append-only record of the transactions that have been executed by the CCF service. It is written by the primary node when a transaction is executed and replicated to all backups which maintain their own duplicated copy. Each node in a network creates and maintains its own local copy of the ledger. Committed entries are always identical between :ref:`a majority <overview/consensus:CFT Consensus Protocol>` of nodes, but a node may be more or less up to date, and uncommitted entries may differ.

On each node, the ledger is written to disk in a directory specified by the ``--ledger-dir`` command line argument to ``cchost``.

It is also possible to specify an optional `read-only` ledger directory ``--read-only-ledger-dir`` to ``cchost``. This enables CCF to have access to historical transactions, for example after joining from a snapshot (see :ref:`operations/ledger_snapshot:Historical Transactions`). Note that only committed ledger files (those whose name ends with ``.committed``) can be read from this directory.

File Layout
~~~~~~~~~~~

The ledger growths as transactions mutate CCF's key-value store. The ledger is split into multiple files (or chunks) written by a node in the directory specified by the ``--ledger-dir`` command line argument to ``cchost``. Even though there are multiple ledger files on disk, there is only one unique `logical` ledger file for the lifetime of a CCF service (and across recoveries). The `logical` ledger can be reconstituted by parsing the ledger files in sequence, based on the sequence number included in their file names.

.. note:: The size of each ledger file is controlled by the ``--ledger-chunk-bytes`` command line argument to ``cchost``.

Ledger files containing only committed entries are named ``ledger_<start_seqno>-<end_seqno>.committed``, with ``<start_seqno>`` and ``<end_seqno>`` the sequence number of the first and last transaction in the ledger, respectively. These files are closed and immutable and it is safe to replicate them to backup storage. They are identical across nodes, provided ``--ledger-chunk-bytes`` has been set to the same value.

Ledger files that still contain some uncommitted entries are named ``ledger_<start_seqno>-<end_seqno>`` or ``ledger_<start_seqno>`` for the most recent one. These files are typically held open by the ``cchost`` process, which may modify their content, or even erase them completely. Uncommitted ledger files may differ arbitrarily across nodes.

.. warning:: Removing `uncommitted` ledger files from the ``--ledger-dir`` ledger directory may cause a node to crash. It is however safe to move `committed` ledger files to another directory, accessible to a CCF node via the ``--read-only-ledger-dir`` command line argument.

It is important to note that while all entries stored in ledger files ending in ``.committed`` are committed, not all committed entries are stored in such a file at any given time. A number of them are typically in the in-progress files, waiting to be flushed to a ``.committed`` file once the size threshold (``--ledger-chunk-bytes``) is met.

The listing below is an example of what a ledger directory may look like:

.. code-block:: bash

    $ cchost --ledger-dir $LEDGER_DIR ...
    $ ls -la $LEDGER_DIR
    -rw-rw-r-- 1 user user 1.6M Jan 31 14:00 ledger_1-7501.committed
    ...
    -rw-rw-r-- 1 user user 1.1M Jan 31 14:00 ledger_92502-97520.committed
    -rw-rw-r-- 1 user user 553K Jan 31 14:00 ledger_97521 # File still in progress

Snapshots
---------

When a node is added to an existing service, the entire transaction history is automatically replicated to this new node. Similarly, on recovery, the transaction history since the creation of the service has to be replayed. Depending on the number of historical transactions, adding a node/recovering a service can take some non-negligible period of time, preventing the new node to quickly take part in the consensus and compromising the availability of the service.

To avoid this, it is possible for a new node to be added (or a service to be recovered) from an existing snapshot of the recent CCF state. In this case, only historical transactions between the sequence number at which the snapshot was taken and the latest state will be replicated.

Snapshot Generation
~~~~~~~~~~~~~~~~~~~

Snapshots are generated at regular intervals by the current primary node and stored under the directory specified via the ``--snapshot-dir`` CLI option (defaults to ``snapshots/``). The transaction interval at which snapshots are generated is specified via the ``--snapshot-tx-interval`` CLI option (defaults to a new snapshot generated every ``10,000`` committed transactions).

.. note:: Because the generation of a snapshot requires a new ledger chunk to be created (see :ref:`operations/ledger_snapshot:File Layout`), all nodes in the network must be started with the same ``--snapshot-tx-interval`` value.

To guarantee that the identity of the primary node that generated the snapshot can be verified offline, the SHA-256 digest of the snapshot (i.e. evidence) is recorded in the ``public:ccf.gov.snapshot_evidence`` table. The snapshot evidence will be signed by the primary node on the next signature transaction (see :ref:`operations/start_network:Signature Interval`).

Committed snapshot files are named ``snapshot_<seqno>_<evidence_seqno>.commited_<evidence_commit_seqno>``, with ``<seqno>`` the sequence number of the state of the key-value store at which they were generated, ``<evidence_seqno>`` the sequence number at which the snapshot evidence was recorded and ``<evidence_commit_seqno>`` the sequence number at which the snapsot evidence was committed.

Uncommitted snapshot files, i.e. those whose evidence has not yet been committed, are named ``snapshot_<seqno>_<evidence_seqno>``. These files will be ignored by CCF when joining or recovering a service as no evidence can attest of their validity.

Join/Recover From Snapshot
~~~~~~~~~~~~~~~~~~~~~~~~~~

Once a snapshot has been generated by the primary, operators can copy or mount the snapshot directory to the new node directory before it is started. On start-up, the new node will automatically resume from the latest committed snapshot file in the ``--snapshot-dir`` directory. If no snapshot file is found, all historical transactions will be replicated to that node.

To validate the snapshot a node is added from, the node first replays the transactions in the ledger following the snapshot until the proof that the snapshot was committed by the service to join is found. This process requires operators to copy the ledger suffix to the node's ledger directory. The validation procedure is generally quick and the node will automatically join the service one the snapshot has been validated. On recovery, the snapshot is automatically verified as part of the usual ledger recovery procedure.

For example, if a node is added using the ``snapshot_1000_1250.committed_1300`` snapshot file, operators should copy the ledger files containing all the sequence numbers between ``1000`` to ``1300`` to the directories specified by ``--ledger-dir`` (or ``--read-only ledger-dir``). This would involve copying the ledger files following the snapshot sequence number ``1000`` until the evidence commit sequence number ``1300``, e.g. ``ledger_1001-1200.committed`` and ``ledger_1201-1500.committed``, to the joining node's ledger directory.

.. note:: If the snapshot to join/recover from is recent, it is likely that the evidence for that snapshot is included in the latest `uncommitted` ledger file. In this case, the corresponding ledger file(s) should be copied to the node's main ledger directory (as specified by ``--ledger-dir``) before start-up.

Historical Transactions
~~~~~~~~~~~~~~~~~~~~~~~

Nodes that started from a snapshot can still process historical queries if the historical ledger files (i.e. the ledger files preceding the snapshot) are made accessible to the node via the ``--read-only-ledger-dir`` option to ``cchost``. Although the read-only ledger directory must be specified to the node on start-up, the historical ledger files can be copied to this directory `after` the node is started.

Best Practices
--------------

It is recommended for operators to backup the ledger and snapshot files as soon as they become committed (i.e. ``.committed`` included in file name). While a majority of nodes will eventually have an identical copy of the ledger, the ledger file should be the most up-to-date on the current primary node. Snapshot files are only generated by the current primary node. As such, monitoring the directories specified by ``--ledger-dir`` and ``--snapshot-dir`` for the `current` primary node allows operators to retrieve the latest ledger and snapshot files.

A low value for ``--ledger-chunk-bytes`` means that smaller ledger files are generated and can thus be backed up by operators more regularly, at the cost of having to manage a large number of ledger files.

.. note:: Uncommitted ledger files (which are likely to contain committed transactions) can also be used on join/recovery, as long as they are copied to the node's ``--ledger-dir`` directory.

Similarly, a low value for ``--snapshot-tx-interval`` means that snapshots are generated often and that join/recovery time will be short, at the cost of additional workload of the primary node for snapshot generation.