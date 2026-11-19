Indexing
========

CCF supports the creation of endpoints which process historical state.
Historical transactions are asynchronously fetched from the ledger, verified and decrypted, and presented to the application endpoint for processing (see :ref:`build_apps/example_cpp:Historical Queries`).
Fetching each transaction on-demand is too slow for some use cases, especially for historical queries which are called regularly or which span many transactions.
To improve the performance of this kind of query, CCF provides an indexing system: applications install a :cpp:type:`ccf::indexing::Strategy`, which is given every committed transaction in order and builds its own index ahead of user queries.
This index is built once but may be queried many times, avoiding repeated fetching and processing of the same transactions.

For instance, to answer a query like "list the TxID of every transaction which wrote to this key", a strategy can record the sequence numbers of those transactions as it sees them, so that the endpoint only needs to fetch the transactions it will actually use.

The indexing system and all the strategies it manages run inside the node, so have the same trust guarantees as any other code running in the node.
Users can trust that indexed results are accurate and complete, and strategies may process private data.
Indexes are node-local: they are never replicated or shared between nodes, and are rebuilt from the ledger by each node.

Strategies
----------

Strategies are C++ classes deriving from :cpp:type:`ccf::indexing::Strategy`.
An application creates an instance on each node and installs it with ``context.get_indexing_strategies().install_strategy()``, typically when its endpoints are initialised (for example in ``init_handlers()``), and queries it from endpoint handlers.
Strategies can also be installed and uninstalled later, for example from an endpoint, as illustrated by the ``CommittedRecords`` strategy in the :ccf_repo:`C++ logging sample <samples/apps/logging/logging.cpp>`.
A strategy implements:

- ``handle_committed_transaction()``, which receives the :term:`Transaction ID` and the contents of each committed transaction, in order.
  The given store contains only the writes made by that transaction.
- ``next_requested()``, which returns the sequence number of the next transaction the strategy wants to receive, or ``std::nullopt`` if it does not currently want any more.
  This allows strategies to start from a later point in the ledger, to stop at an upper bound, or to restart from the beginning.
- Optionally, ``tick()``, which is called before each batch of transactions is requested, and ``describe()``, which returns a JSON summary of the strategy's state.
  The descriptions of all installed strategies are returned by the :http:GET:`/node/index/strategies` endpoint.

CCF provides the following strategies, which applications can use directly or extend:

- ``VisitEachEntryInMap`` requests every transaction in order, and calls ``visit_entry()`` for each key-value pair written to a target map.
  It is the base for the other built-in strategies.
- ``SeqnosByKey_InMemory<M>`` records, in memory, the sequence number of every transaction which writes to each key of a map ``M``.
- ``SeqnosByKey_Bucketed<M>`` records the same information, but bounds its memory use by offloading completed ranges of results to disk (see `Bucketed Strategies`_).
  ``SeqnosForValue_Bucketed<V>`` applies the same approach to a single-value map ``V``.
- ``LazyStrategy<Base>`` wraps another strategy so that it only indexes transactions up to the highest sequence number passed to ``extend_index_to()``, rather than indexing the whole ledger eagerly.
  The C++ logging sample uses ``LazyStrategy<SeqnosByKey_Bucketed<RecordsMap>>`` to serve historical range queries (see :ref:`build_apps/example_cpp:Indexing`).

Query methods such as ``get_write_txs_in_range()`` return ``std::nullopt`` when the requested range has not yet been indexed, or when the results are not yet available in memory.
Endpoints should then ask the caller to retry later, for example with a ``202 Accepted`` response.

Scheduling
----------

Each node has a single indexer which manages all installed strategies.
It runs as a periodic task, at the interval given by the node's ``tick_interval`` configuration entry.
On each run, the indexer:

1. Reads the node's current commit point.
2. Calls ``tick()`` on every installed strategy, then collects the sequence number each strategy requests next with ``next_requested()``.
3. If the earliest requested transaction is committed, requests a bounded batch of committed transactions starting from it, through the same historical state cache used by historical queries.
   Fetching transactions from the ledger is asynchronous, so a batch may only become available on a later run.
4. Passes each fetched transaction, in order, to every strategy whose ``next_requested()`` matches its sequence number.

Strategies therefore only ever receive committed transactions, and each strategy receives them in sequence number order.
The indexer does not index transactions which are not yet committed.

Bucketed Strategies
-------------------

An index which records every matching transaction may grow linearly with the ledger.
To bound memory use, ``SeqnosByKey_Bucketed`` divides the sequence number space into fixed-size buckets (``seqnos_per_bucket``, 1000 by default).
For each key, only the bucket covering the most recently indexed writes is held in memory.
When a write to that key falls into a later bucket, the completed bucket, and an empty bucket for every intervening range, is written to disk using the LFS system described below.

To answer a query, the strategy loads the buckets covering the requested range from disk into a least-recently-used cache holding at most ``max_buckets`` buckets (10 by default).
A single query may therefore cover at most ``(max_buckets - 1) * seqnos_per_bucket`` transactions; larger ranges are rejected with an exception.
While any required bucket is still being loaded, the query returns ``std::nullopt``, and a later query returns the complete result once loading has finished.

``SeqnosByKey_Bucketed`` and ``SeqnosForValue_Bucketed`` can only be constructed for public maps.
Applications which need to index private maps can use an in-memory strategy, or implement their own.

Rebuilding the Index
~~~~~~~~~~~~~~~~~~~~

If a ``SeqnosByKey_Bucketed`` query encounters a missing or corrupt required index file, it requests a rebuild and returns ``std::nullopt``.
All subsequent queries remain unavailable until the indexing thread resets the index on its next strategy tick.
Indexing then restarts from transaction 1, and queries remain unavailable until their requested range has been indexed and any required files have been fetched again.

LFS
---

The LFS (Large File Storage) system offloads blobs of data from a node's memory to files on its local disk, and fetches them back asynchronously.
It is currently used only by the bucketed indexing strategies.
The local disk is outside the node's trust boundary, so the LFS system protects the confidentiality and integrity of what it stores:

- On startup, each node generates a fresh random AES-GCM key, which is held only in the node's memory and is never written to disk or shared.
  Only the node instance which wrote a file can read it back.
- Since files written by a previous instance cannot be decrypted, a node deletes any existing index directory (``.index``, relative to the node's working directory) on startup, and rebuilds its indexes from the ledger.
- Each blob is identified by a name chosen by the strategy, which may contain information about the indexed data, such as a key.
  The file is instead named after the hex-encoded SHA-256 digest of this name.
- The contents are prefixed with the obfuscated name, then encrypted with the node's key and a random IV for each write.
- When a blob is fetched, the file is authenticated and decrypted, and the embedded name is compared with the requested one, so that a file that was modified, truncated, or swapped with another file is detected.
  Files larger than any blob this node has written are rejected before being read.
  A missing file is reported as not found, and a file which fails any of these checks as corrupt.
  In either case, the bucketed strategies rebuild their index as described in `Rebuilding the Index`_.

Writes and reads are performed on a single ordered task queue, so a fetch issued after a store of the same blob always observes the stored file.

File names are hashed and contents are encrypted, but the files are not padded.
The number, sizes and access patterns of index files are visible to anyone with access to the node's disk, and may reveal information about the distribution of writes in the indexed public map.
