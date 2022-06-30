Ledger and Snapshots
====================

The ledger and snapshot files written by CCF nodes to disk should be managed by operators to allow for safe backup of the service and application state as well as fast join and recovery procedures. This section describes how these files are generated and how operators should manage them effectively.

.. note:: See the :doc:`/audit/index` section to read about offline ledger auditability.

Ledger
------

The ledger is the persistent replicated append-only record of the transactions that have been executed by the CCF service. It is written by the primary node when a transaction is executed and replicated to all backups which maintain their own duplicated copy. Each node in a network creates and maintains its own local copy of the ledger. Committed entries are always byte identical between :ref:`a majority <architecture/consensus/index:CFT Consensus Protocol>` of nodes, but a node may be more or less up to date, and uncommitted entries may differ.

On each node, the ledger is written to disk in a directory specified by the ``ledger.directory`` configuration entry.

It is also possible to specify optional `read-only` ledger directories ``ledger.read_only_directories``. This enables CCF to have access to historical transactions, for example after joining from a snapshot (see :ref:`operations/ledger_snapshot:Historical Transactions`). Note that only committed ledger files (those whose name ends with ``.committed``) can be read from this directory. This option can be used to specify a shared directory that all nodes in the network can access to serve historical ledger entries.

File Layout
~~~~~~~~~~~

The ledger growths as transactions mutate CCF's key-value store. The ledger is split into multiple files (or chunks) written by a node in the directory specified by the ``ledger.directory`` configuration entry. Even though there are multiple ledger files on disk, there is only one unique `logical` ledger file for the lifetime of a CCF service (and across recoveries). The `logical` ledger can be reconstituted by parsing the ledger files in sequence, based on the sequence number included in their file names.

.. note:: The size of each ledger file is controlled by the ``ledger.chunk_size`` configuration entry.

Ledger files containing only committed entries are named ``ledger_<start_seqno>-<end_seqno>.committed``, with ``<start_seqno>`` and ``<end_seqno>`` the sequence number of the first and last transaction in the ledger, respectively. These files are closed and immutable and it is safe to replicate them to backup storage. They are identical across nodes, provided ``ledger.chunk_size`` has been set to the same value.

Ledger files that still contain some uncommitted entries are named ``ledger_<start_seqno>-<end_seqno>`` or ``ledger_<start_seqno>`` for the most recent one. These files are typically held open by the ``cchost`` process, which may modify their content, or even erase them completely. Uncommitted ledger files may differ arbitrarily across nodes.

.. warning:: Removing `uncommitted` ledger files from the ``ledger.directory`` directory may cause a node to crash. It is however safe to move `committed` ledger files to another directory, accessible to a CCF node via the ``ledger.read_only_directories`` configuration entry.

It is important to note that while all entries stored in ledger files ending in ``.committed`` are committed, not all committed entries are stored in such a file at any given time. A number of them are typically in the in-progress files, waiting to be flushed to a ``.committed`` file once the size threshold (``ledger.chunk_size``) is met.

The listing below is an example of what a ledger directory may look like:

.. code-block:: bash

    $ cchost # with ledger.ledger-dir = $LEDGER_DIR
    $ ls -la $LEDGER_DIR
    -rw-rw-r-- 1 user user 1.6M Jan 31 14:00 ledger_1-7501.committed
    ...
    -rw-rw-r-- 1 user user 1.1M Jan 31 14:00 ledger_92502-97520.committed
    -rw-rw-r-- 1 user user 553K Jan 31 14:00 ledger_97521 # File still in progress

.. note::

    - While the :doc:`/operations/recovery` procedure is in progress, new ledger files are suffixed with ``.recovery``. These files are automatically renamed (i.e. recovery suffix removed) once the recovery procedure is complete. ``.recovery`` files are automatically discarded on node startup so that a failed recovery attempt does not prevent further recoveries.
    - A new ledger chunk can also be created by the ``trigger_ledger_chunk`` governance action, which will automatically produce a new chunk at the following signature transaction.

Snapshots
---------

When a node is added to an existing service, the entire transaction history is automatically replicated to this new node. Similarly, on recovery, the transaction history since the creation of the service has to be replayed. Depending on the number of historical transactions, adding a node/recovering a service can take some non-negligible period of time, preventing the new node to quickly take part in the consensus and compromising the availability of the service.

To avoid this, it is possible for a new node to be added (or a service to be recovered) from an existing snapshot of the recent CCF state. In this case, only historical transactions between the sequence number at which the snapshot was taken and the latest state will be replicated.

Snapshot Generation
~~~~~~~~~~~~~~~~~~~

Snapshots are generated at regular intervals by the current primary node and stored under the directory specified via the ``snapshots.directory`` configuration entry (defaults to ``snapshots/``). The transaction interval at which snapshots are generated is specified via the ``snapshots.tx_count`` configuration entry (defaults to a new snapshot generated every ``10,000`` committed transactions). Snapshots can also be generated by the ``trigger_snapshot`` governance action, i.e. by submitting a proposal. A snapshot will then be generated at the next signature transaction.

.. note:: Because the generation of a snapshot requires a new ledger chunk to be created (see :ref:`operations/ledger_snapshot:File Layout`), all nodes in the network must be started with the same ``snapshots.tx_count`` value.

To guarantee that the identity of the primary node that generated the snapshot can be verified offline, the SHA-256 digest of the snapshot (i.e. evidence) is recorded in the ``public:ccf.internal.snapshot_evidence`` table. The snapshot evidence will be signed by the primary node on the next signature transaction (see :ref:`operations/configuration:``ledger_signatures```).

Committed snapshot files are named ``snapshot_<seqno>_<evidence_seqno>.committed``, with ``<seqno>`` the sequence number of the state of the key-value store at which they were generated and ``<evidence_seqno>`` the sequence number at which the snapshot evidence was recorded.

Uncommitted snapshot files, i.e. those whose evidence has not yet been committed, are named ``snapshot_<seqno>_<evidence_seqno>``. These files will be ignored by CCF when joining or recovering a service as no evidence can attest of their validity.

Join/Recover From Snapshot
~~~~~~~~~~~~~~~~~~~~~~~~~~

Once a snapshot has been generated by the primary, operators can copy or mount the `read-only` snapshot directory to the new node directory before it is started. On start-up, the new node will automatically resume from the latest committed snapshot file in the ``snapshots.directory`` directory. If no snapshot file is found, all historical transactions will be replicated to that node.

From 2.x releases, committed snapshot files embed the receipt of the evidence transaction. As such, nodes can join or recover a service from a standalone snapshot file. For 1.x releases, it is expected that operators also copy the ledger suffix containing the proof of commit of the evidence transaction to the node's ledger directory.

It is important to note that new nodes cannot resume from a snapshot and join a service via a node that started from a more recent snapshot. For example, if a new node resumes from a snapshot generated at ``seqno 100`` and joins from a (primary) node that originally resumed from a snapshot at ``seqno 50``, the new node will throw a ``StartupSeqnoIsOld`` error shortly after starting up. It is expected that operators copy the *latest* committed snapshot file to new nodes before start up.

.. note:: Snapshots emitted by 1.x nodes can be used by 2.x nodes to join or a recover a service.

Historical Transactions
~~~~~~~~~~~~~~~~~~~~~~~

Nodes that started from a snapshot can still process historical queries if the historical ledger files (i.e. the ledger files preceding the snapshot) are made accessible to the node via the ``ledger.read_only_directories`` option to ``cchost``. Although the read-only ledger directory must be specified to the node on start-up, the historical ledger files can be copied to this directory `after` the node is started.

Best Practices
--------------

It is recommended for operators to backup the ledger and snapshot files as soon as they become committed (i.e. ``.committed`` included in file name). While a majority of nodes will eventually have an identical copy of the ledger, the ledger file should be the most up-to-date on the current primary node. Snapshot files are only generated by the current primary node. As such, monitoring the directories specified by ``ledger.directory`` and ``snapshots.directory`` for the `current` primary node allows operators to retrieve the latest ledger and snapshot files.

.. tip:: Committed ledger and snapshot files can be copied to shared directories made available to all nodes in the network via the ``ledger.read_only_directories`` and ``snapshots.read_only_directory`` configuration entries, respectively. Note that it is the responsibility of the operator to move/copy these files safely to avoid "ledger holes", i.e. historical ledger files not being available to a new node that started from a recent snapshot.

A low value for ``ledger.chunk_size`` means that smaller ledger files are generated and can thus be backed up by operators more regularly, at the cost of having to manage a large number of ledger files.

Similarly, a low value for ``snapshots.tx_count`` means that snapshots are generated often and that join/recovery time will be short, at the cost of additional workload on the primary node for snapshot generation.

.. note:: Uncommitted ledger files (which are likely to contain committed transactions) should also be used on recovery, as long as they are copied to the node's ``ledger.directory`` directory.

Invariants
----------

1. To facilitate audit and verification of the integrity of the ledger, individual ledger files always end on a signature transaction.

2. For operator convenience, all committed ledger files (``.committed`` suffix) are the same on all up-to-date nodes. More precisely, among up-to-date nodes:

- Committed ledger files start and end at the same ``seqno``.
- Committed ledger files with the same name are byte-identical.

3. Snapshots are always generated for the ``seqno`` of a signature transaction (but not all signature transactions trigger the generation of snapshot).

4. The generation of a snapshot triggers the creation of a new ledger file. This is a corollary of 2. and 3., since new nodes should be able to join from a snapshot only and generate further ledger files that are the same as on the other nodes.
