Ledger and Snapshots
====================

The ledger and snapshot files written by CCF nodes to disk should be managed by operators to allow for safe backup of the service and application state as well as fast join and recovery procedures. This section describes how these files are generated and how operators should manage them effectively.

.. note:: See the :doc:`/audit/index` section to read about offline ledger auditability.

Ledger
------

The ledger is the persistent replicated append-only record of the transactions that have been executed by the CCF service. It is written by the primary node when a transaction is executed and replicated to all backups which maintain their own duplicated copy. Each node in a network creates and maintains its own local copy of the ledger. Committed entries are always byte identical between :ref:`a majority <architecture/consensus/index:Consensus Protocol>` of nodes, but a node may be more or less up to date, and uncommitted entries may differ.

On each node, the ledger is written to disk in a directory specified by the ``ledger.directory`` configuration entry.

It is also possible to specify optional `read-only` ledger directories ``ledger.read_only_directories``. This enables CCF to have access to historical transactions, for example after joining from a snapshot (see :ref:`operations/ledger_snapshot:Historical Transactions`). Note that only committed ledger files (those whose name ends with ``.committed``) can be read from this directory. This option can be used to specify a shared directory that all nodes in the network can access to serve historical ledger entries.

File Layout
~~~~~~~~~~~

The ledger grows as transactions mutate CCF's key-value store. The ledger is split into multiple files (or chunks) written by a node in the directory specified by the ``ledger.directory`` configuration entry. Even though there are multiple ledger files on disk, there is only one unique `logical` ledger file for the lifetime of a CCF service (and across recoveries). The `logical` ledger can be reconstituted by parsing the ledger files in sequence, based on the sequence number included in their file names.

.. note:: The size of each ledger file is controlled by the ``ledger.chunk_size`` configuration entry.

Ledger files containing only committed entries are named ``ledger_<start_seqno>-<end_seqno>.committed``, with ``<start_seqno>`` and ``<end_seqno>`` the sequence number of the first and last transaction in the ledger, respectively. These files are closed and immutable and it is safe to replicate them to backup storage. They are identical across nodes, provided ``ledger.chunk_size`` has been set to the same value.

Ledger files that still contain some uncommitted entries are named ``ledger_<start_seqno>-<end_seqno>`` or ``ledger_<start_seqno>`` for the most recent one. These files are typically held open by the node process, which may modify their content, or even erase them completely. Uncommitted ledger files may differ arbitrarily across nodes.

.. warning:: Removing `uncommitted` ledger files from the ``ledger.directory`` directory may cause a node to crash. It is however safe to move `committed` ledger files to another directory, accessible to a CCF node via the ``ledger.read_only_directories`` configuration entry.

It is important to note that while all entries stored in ledger files ending in ``.committed`` are committed, not all committed entries are stored in such a file at any given time. A number of them are typically in the in-progress files, waiting to be flushed to a ``.committed`` file once the size threshold (``ledger.chunk_size``) is met.

The listing below is an example of what a ledger directory may look like:

.. code-block:: bash

    $ ls -la $LEDGER_DIR
    -rw-rw-r-- 1 user user 1.6M Jan 31 14:00 ledger_1-7501.committed
    ...
    -rw-rw-r-- 1 user user 1.1M Jan 31 14:00 ledger_92502-97520.committed
    -rw-rw-r-- 1 user user 553K Jan 31 14:00 ledger_97521 # File still in progress

.. note::

    - While the :doc:`/operations/recovery` procedure is in progress, new ledger files are suffixed with ``.recovery``. These files are automatically renamed (i.e. recovery suffix removed) once the recovery procedure is complete. ``.recovery`` files are automatically discarded on node startup so that a failed recovery attempt does not prevent further recoveries.
    - A new ledger chunk can also be created by the ``trigger_ledger_chunk`` governance action, which will automatically produce a new chunk at the following signature transaction.

Download Endpoints
~~~~~~~~~~~~~~~~~~

In order to faciliate long term backup of the ledger, nodes can enable HTTP endpoints that allow a client to download committed ledger files.
These endpoints are disabled by default and can be enabled by adding `LedgerChunkDownload` to `enabled_operator_features` on `rpc_interfaces` in the node configuration.

:http:HEAD:`/node/ledger-chunk/<chunk-name>` and :http:GET:`/node/ledger-chunk/<chunk-name>`

These endpoints allow downloading a specific ledger chunk by name, where `<chunk-name>` is of the form `ledger_<start_seqno>-<end_seqno>.committed`.
They support the HTTP `Range` header for partial downloads, and the `HEAD` method for clients to query metadata such as the total size without downloading the full chunk.
They also populate the `x-ms-ccf-ledger-chunk-name` response header with the name of the chunk being served.

:http:HEAD:`/node/ledger-chunk?since=<seqno>` and :http:GET:`/node/ledger-chunk?since=<seqno>`

These endpoints can be used by a client to download the next ledger chunk including a given sequence number `<seqno>`.
The redirects to the appropriate chunk if it exists, using the previous set of endpoints, or returns a `404 Not Found` response if no such chunk is available.

Snapshots
---------

When a node is added to an existing service, the entire transaction history is automatically replicated to this new node. Similarly, on recovery, the transaction history since the creation of the service has to be replayed. Depending on the number of historical transactions, adding a node/recovering a service can take some non-negligible period of time, preventing the new node to quickly take part in the consensus and compromising the availability of the service.

To avoid this, it is possible for a new node to be added (or a service to be recovered) from an existing snapshot of the recent CCF state. In this case, only historical transactions between the sequence number at which the snapshot was taken and the latest state will be replicated.

Snapshot Generation
~~~~~~~~~~~~~~~~~~~

Snapshots are generated at regular intervals by the current primary node and stored under the directory specified via the ``snapshots.directory`` configuration entry (defaults to ``snapshots/``). The transaction interval at which snapshots are generated is specified via the ``snapshots.tx_count`` configuration entry (defaults to a new snapshot generated every ``10,000`` committed transactions). Snapshots can also be generated by the ``trigger_snapshot`` governance action, i.e. by submitting a proposal. A snapshot will then be generated at the next signature transaction.

.. note:: Because the generation of a snapshot requires a new ledger chunk to be created (see :ref:`operations/ledger_snapshot:File Layout`), all nodes in the network must be started with the same ``snapshots.tx_count`` value.

To guarantee that the identity of the primary node that generated the snapshot can be verified offline, the SHA-256 digest of the snapshot (i.e. evidence) is recorded in the :ref:`audit/builtin_maps:``snapshot_evidence``` table. The snapshot evidence will be signed by the primary node on the next signature transaction (see :ref:`operations/configuration:``ledger_signatures```).

Committed snapshot files are named ``snapshot_<seqno>_<evidence_seqno>.committed``, with ``<seqno>`` the sequence number of the state of the key-value store at which they were generated and ``<evidence_seqno>`` the sequence number at which the snapshot evidence was recorded.

Uncommitted snapshot files, i.e. those whose evidence has not yet been committed, are named ``snapshot_<seqno>_<evidence_seqno>``. These files will be ignored by CCF when joining or recovering a service as no evidence can attest of their validity.

Join or Recover From Snapshot
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Joining nodes will request a snapshot from the target service to accelerate their join. This behaviour is controlled by the ``command.join.fetch_recent_snapshot`` configuration option, and enabled by default. This removes the need for a shared read-only snapshot mount, and corresponding operator actions to keep it up-to-date. Instead the joiner will send a sequence of HTTP requests, potentially following redirect responses to find the current primary and request a specific snapshot, to download a recent snapshot which should allow them to join rapidly. Any suffix after a snapshot (including the entire ledger, in the rare cases where no snapshot can be found) will be replicated to that node via the consensus protocol.

The legacy behaviour without ``fetch_recent_snapshot`` relies on a shared read-only directory. On start-up, the new node will search both ``snapshot.directory`` and ``read_only_directory`` to find the latest committed snapshot file. Operators are responsible for populating these with recent snapshots emitted by the service, and making this available (such as via a shared read-only mounted) on joining nodes.

It is important to note that new nodes cannot join a service if the snapshot they start from is older than the snapshot the primary node started from. For example, if a new node resumes from a snapshot generated at ``seqno 50`` and joins from a (primary) node that originally resumed from a snapshot at ``seqno 100``, the new node will throw a ``StartupSeqnoIsOld`` error shortly after starting up. It is expected that operators copy the *latest* committed snapshot file to new nodes before start up.

Historical Transactions
~~~~~~~~~~~~~~~~~~~~~~~

Nodes that started from a snapshot can still process historical queries if the historical ledger files (i.e. the ledger files preceding the snapshot) are made accessible to the node via the ``ledger.read_only_directories`` configuration option. Although the read-only ledger directory must be specified to the node on start-up, the historical ledger file contents can be copied to this directory `after` the node is started (see :ref:`operations/data_persistence:Data Persistence`).

Before these ledger files are present the node will be functional, participating in consensus and able to accept new transactions, but historical queries targeting the missing entries will permanently stall. Calls to the historical query APIs will return loading responses, as these APIs do not currently distinguish between temporarily missing and permanently missing files. It is the responsibility of the operator to ensure that the ledger files visible to all nodes are complete, including back-filling missing files when required.

Invariants
----------

1. To facilitate audit and verification of the integrity of the ledger, individual ledger files always end on a signature transaction.

2. For operator convenience, all committed ledger files (``.committed`` suffix) are the same on all up-to-date nodes. More precisely, among up-to-date nodes:

- Committed ledger files start and end at the same ``seqno``.
- Committed ledger files with the same name are byte-identical.

3. Snapshots are always generated for the ``seqno`` of a signature transaction (but not all signature transactions trigger the generation of snapshot).

4. The generation of a snapshot triggers the creation of a new ledger file. This is a corollary of 2. and 3., since new nodes should be able to join from a snapshot only and generate further ledger files that are the same as on the other nodes.
