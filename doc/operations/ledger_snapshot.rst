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

In order to faciliate long term backup of the ledger files (also called chunks), nodes can enable HTTP endpoints that allow a client to download committed ledger files.
The `LedgerChunkDownload` feature must be added to `enabled_operator_features` on the relevant `rpc_interfaces` entries in the node configuration.

1. :http:GET:`/node/ledger-chunk` and :http:HEAD:`/node/ledger-chunk`, both taking a `seqno` query parameter.

These endpoints can be used by a client to download the next ledger chunk including a given sequence number `<seqno>`.
They redirect to the appropriate chunk if it exists, using the endpoints described below, or return a `404 Not Found` response if no such chunk is available.

In the typical case, a requesting client will first hit a Backup, and will eventually work its way to chunks recent enough that only the primary can provide them:

.. mermaid::

    sequenceDiagram
        Note over Client: Client asks for chunk starting at index
        Client->>+Backup: GET /node/ledger-chunk?since=index
        Backup->>-Client: 308 Location: /node/ledger-chunk/ledger_startIndex_endIndex.committed
        Note over Backup: Backup node has that chunk
        Client->>+Backup: GET /node/ledger-chunk/ledger_startIndex_endIndex.committed
        Backup->>-Client: 200 <Chunk Contents>
        Client->>+Backup: GET /node/ledger-chunk?since=endIndex+1
        Note over Backup: Backup node does not yet have a committed chunk starting at endIndex+1
        Backup->>-Client: 308 Location: https://primary/node/ledger-chunk?since=endIndex+1
        Client->>+Primary: GET /node/ledger-chunk?since=endIndex+1
        Primary->>-Client: 308 Location: /node/ledger-chunk/ledger_endIndex+1_nextEndIndex.committed
        Client->>+Primary: GET /node/ledger-chunk/ledger_startIndex_endIndex.committed
        Note over Primary: But the Primary node has the most recent chunk already
        Primary->>-Client: 200 <Chunk Contents>

But it is also possible for a client to first hit a node that has recently started from a snapshot, and does not have some past chunks as a result.
If the Primary started from `snapshot_100.committed` and locally has:

.. code-block:: bash

    ledger_1-50.committed
    ledger_101-150.committed

and Backup has:

.. code-block:: bash

    ledger_1-50.committed
    ledger_51-100.committed

then the following sequence can occur:

.. mermaid::

    sequenceDiagram
        Client->>+Primary: GET /node/ledger-chunk?since=51
        Primary->>-Client: 308 Location: https://backup/node/ledger-chunk?since=51
        Client->>+Backup: GET /node/ledger-chunk?since=51
        Backup->>-Client: 308 Location: /node/ledger-chunk/ledger_51-100.committed
        Client->>+Backup: GET /node/ledger-chunk/ledger_51-100.committed
        Backup->>-Client: 200 <Chunk Contents>
        Client->>+Backup: GET /node/ledger-chunk?since=101
        Note over Backup: Backup node does not have 101-150
        Backup->>-Client: 308 Location: https://primary/node/ledger-chunk?since=51
        Client->>+Primary: GET /node/ledger-chunk?since=101

2. :http:GET:`/node/ledger-chunk/{chunk_name}` and :http:HEAD:`/node/ledger-chunk/{chunk_name}`

These endpoints allow downloading a specific ledger chunk by name, where `<chunk-name>` is of the form `ledger_<start_seqno>-<end_seqno>.committed`.
They support the HTTP `Range` header for partial downloads, and the `HEAD` method for clients to query metadata such as the total size without downloading the full chunk.
They also populate the `x-ms-ccf-ledger-chunk-name` response header with the name of the chunk being served.

Want-Repr-Digest and Repr-Digest
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These endpoints also support the ``Want-Repr-Digest`` request header (`RFC 9530 <https://www.rfc-editor.org/rfc/rfc9530>`_).
When set, the response will include a ``Repr-Digest`` header containing the digest of the full representation of the file.
Supported algorithms are ``sha-256``, ``sha-384``, and ``sha-512``. If the header contains only unsupported or invalid algorithms, the server defaults to ``sha-256`` (as permitted by `RFC 9530 Appendix C.2 <https://www.rfc-editor.org/rfc/rfc9530#appendix-C.2>`_).
For example, a client sending ``Want-Repr-Digest: sha-256=1`` will receive a header such as ``Repr-Digest: sha-256=:AEGPTgUMw5e96wxZuDtpfm23RBU3nFwtgY5fw4NYORo=:`` in the response.
This allows clients to verify the integrity of downloaded files and avoid re-downloading files they already hold by comparing digests.

.. note:: The ``Want-Repr-Digest`` / ``Repr-Digest`` support also applies to the snapshot download endpoints (:http:GET:`/node/snapshot/{snapshot_name}` and :http:HEAD:`/node/snapshot/{snapshot_name}`).

ETag and If-None-Match
^^^^^^^^^^^^^^^^^^^^^^

``GET /node/ledger-chunk/{chunk_name}`` supports ``ETag`` and ``If-None-Match`` headers, allowing clients to atomically check whether a chunk (or a range of a chunk) has changed and re-download it in a single request, without needing a separate metadata query first.
Every successful ``GET`` response includes an ``ETag`` header whose value uses the `RFC 9530 <https://www.rfc-editor.org/rfc/rfc9530>`_ digest format: ``"sha-256=:<base64_digest>:"``, where ``<base64_digest>`` is the base64-encoded SHA-256 digest of the returned content (which may be a sub-range when the ``Range`` header is used).

.. note:: ETag values must be surrounded by double quotes, as per `RFC 7232 <https://www.rfc-editor.org/rfc/rfc7232#section-2.3>`_.

Clients can send an ``If-None-Match`` request header containing one or more ETags. If the content matches any of the provided ETags, the server responds with ``304 Not Modified`` instead of re-sending the body. The supported digest algorithms are ``sha-256``, ``sha-384``, and ``sha-512``.
When the client already holds a chunk and wants to check if it has changed, it sends the previously received ETag in ``If-None-Match``. If the content has not changed, the server responds with ``304 Not Modified``, saving bandwidth:

.. note:: The node currently defaults to ``sha-256`` for ETags, but clients can also send other supported digest algorithms in the ``If-None-Match`` header, and the server will use the first supported one it finds. For example, if the client sends ``If-None-Match: "sha-384=:AAAA...=:", "sha-256=:47DEQpj8HBSa+/TImW...=:"``, the server will use the ``sha-384`` digest if it supports it, and fall back to ``sha-256`` otherwise.

.. mermaid::

    sequenceDiagram
        Note over Client: Client already has chunk with known ETag
        Client->>+Node: GET /node/ledger-chunk/ledger_1-100.committed<br/>If-None-Match: "sha-256=:47DEQpj8HBSa+/TImW...=:"
        Note over Node: Computes digest, matches If-None-Match
        Node->>-Client: 304 Not Modified<br/>ETag: "sha-256=:47DEQpj8HBSa+/TImW...=:"
        Note over Client: No body transferred, client keeps existing copy

If the ``If-None-Match`` ETag does not match the current content (e.g. the client has an outdated copy, or is checking a different chunk), the server returns the full content as a fresh download:

.. mermaid::

    sequenceDiagram
        Note over Client: Client sends an ETag that does not match
        Client->>+Node: GET /node/ledger-chunk/ledger_1-100.committed<br/>If-None-Match: "sha-256=:AAAA...=:"
        Note over Node: Computes digest, does not match If-None-Match
        Node->>-Client: 200 OK<br/>ETag: "sha-256=:47DEQpj8HBSa+/TImW...=:"<br/><Chunk Contents>
        Note over Client: Client stores chunk and new ETag for future requests

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

Joining nodes will request a snapshot from the target service to accelerate their join. This behaviour is controlled by the ``command.join.fetch_recent_snapshot`` configuration option, and enabled by default. This removes the need for a shared read-only snapshot mount, and corresponding operator actions to keep it up-to-date. Instead, if the joiner is told by the network that the snapshot they have locally is too old, the joiner will send a sequence of HTTP requests, potentially following redirect responses to find the current primary and request a specific snapshot, to download a recent snapshot which should allow them to join rapidly. Any suffix after a snapshot (including the entire ledger, in the rare cases where no snapshot can be found) will be replicated to that node via the consensus protocol.

The legacy behaviour without ``fetch_recent_snapshot`` relies on a shared read-only directory. On start-up, the new node will search both ``snapshot.directory`` and ``read_only_directory`` to find the latest committed snapshot file. Operators are responsible for populating these with recent snapshots emitted by the service, and making this available (such as via a shared read-only mounted) on joining nodes.

In particular, there is hard lower-bound on the age of the snapshot that a joining node can start from. It must be at least as recent as the snapshot that the primary node started from, otherwise the primary will return a ``StartupSeqnoIsOld`` error to the joining node.

The following flowchart summarises the join procedure when ``command.join.fetch_recent_snapshot`` is enabled:

.. mermaid::

  flowchart TD
        startup["Startup"]
    
        select.init_assign("startup_seqno = 0")
        select.next_local["Choose highest local snapshot file A-B.committed"]
        select.verify{"Validate snapshot"}
        select.valid("startup_seqno = A")
        select.delete("Delete invalid snapshot")
    
        test_mode{"mode?"}
    
        join.complete("Joined")
        join.failure["Join failure"]
        join.redirect("target_rpc_address = response.headers['Location']")
        join.response{"Response type?"}
        join.send("Send join request to target_rpc_address, including startup_seqno")
        join.timeout("Timeout")
        
        fetch.apply("startup_seqno = A")
        fetch.begin("peer_address = target_rpc_address")
        fetch.redirect("peer_address = response.headers['Location']")
        fetch.response{"Response type?"}
        fetch.send("{peer_address} GET /snapshot?since={startup_seqno}")
        fetch.fetch("{peer_address} GET /snapshot/{snapshot_name}")
    
        recovery.process("Complete recovery")
        recovery.public("Deserialise snapshot public state")
    
        postjoin.service_open{"Service open?"}
        postjoin.public("Deserialise snapshot public state")
    
        wait_for_open("Wait for service to open")
        secrets_available("Deserialise snapshot private state")
        done["Done"]
    
        startup --> select.init_assign
        subgraph Select local snapshot
            select.init_assign --> select.next_local
            select.next_local --> select.verify
            select.verify -->|Valid| select.valid
            select.verify -->|Invalid| select.delete
            select.delete --> select.next_local
        end
        select.valid --> test_mode
        select.next_local -->|No more snapshots| test_mode
    
        test_mode -->|mode == Join| join.send
        subgraph Join
            join.timeout -.-> join.send
            join.send -->|Response received| join.response
            join.response -->|200 OK| join.complete
            join.response -->|30x Redirect| join.redirect
            join.redirect --> join.send
    
            join.response -->|StartupSeqnoIsOld| fetch.begin
            subgraph FetchSnapshot
                fetch.begin --> fetch.send
                fetch.send -->|Response received| fetch.response
                fetch.response -->|2xx Success| fetch.fetch
                fetch.fetch --> fetch.apply
                fetch.response -->|30x Redirect| fetch.redirect
                fetch.redirect --> fetch.send
            end
            fetch.apply --> join.timeout
            fetch.send -.-> join.timeout
            fetch.response -->|Other error| join.timeout
    
            join.response -.->|Timeout| join.timeout
        end
        join.response -->|Other error| join.failure
    
        join.complete --> postjoin.service_open
    
        subgraph PostJoin
            postjoin.service_open -->|No| postjoin.public
        end
        postjoin.service_open -->|Yes| secrets_available
        postjoin.public --> wait_for_open
    
        test_mode -->|mode == Recovery| recovery.public
        subgraph Recovery
            recovery.public -.-> recovery.process
        end
        recovery.process -.-> wait_for_open
    
        wait_for_open --> secrets_available
        secrets_available --> done


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

4. When a snapshot is generated, it must coincide with the end of a ledger file. Since a node can join using solely a snapshot, the first ledger file on that node will start just after the ``seqno`` of the snapshot. By 2., all nodes must have the same ledger files, so the generation of that snapshot on the primary must trigger the creation of a new ledger file starting at the next ``seqno`` to ensure the primary's ledger files are consistent with the joining node's files.
