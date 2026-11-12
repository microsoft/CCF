Indexing
========

CCF supports the creation of endpoints which process historical state.
Historical transactions are asynchronously fetched from the ledger, verified and decrypted, and presented to the application endpoint for processing.
These queries can also operate on a range of historical transactions, and build an aggregated result.
The framework handles all details of fetching and validating these entries, to present a simple API to the application programmer.

Fetching each transaction on-demand is too slow for some use cases, especially for historical queries which may be called regularly.
To improve the performance of this kind of query, the framework provides a generic indexing system.
Applications can define and install a :cpp:type:`ccf::indexing::Strategy` for processing historical queries.
Each strategy will be given the raw contents of transactions shortly after they are committed, and can build its own index ahead of a user-query.
This index is built once but may be queried many times, preventing duplicate fetches and processing for duplicate queries.

For instance, if we want to answer a query like "tell me the TxID of every transaction which wrote to this table", we could write a strategy which stores a large list of those TxIDs as it sees them.

This indexing system and all the strategies it manages exist entirely within the enclave, so have the same trust guarantees as any other in-enclave code.
This means users can trust that these queries are accurate and complete, and may deal with private data, in a way which is not possible with out-of-enclave ledger processing.

LFS
---

To prevent these indexes from growing indefinitely and exhausting the enclave memory budget, there is an additional system for offloading chunks of memory to the host, to be stored on disk.
In the CCF codebase, this is referred to as the LFS (Large File Storage) system.
In the example above, the list of TxIDs may grow linearly with the ledger.
Rather than holding the entire index in-memory the strategy would offload chunks of it to the host - keeping a small cache in-memory and rapidly available, with the full data set available asynchronously by requesting it from the host.

To maintain the trust guarantees of this offloaded data, it must be carefully handled:

* Integrity protected, to prevent the host tampering with the index.
* Encrypted, to prevent the host reading indexes of confidential state.
* Reproducible, to recover a complete index if the host tampers with or hides the data.
* *Additionally obfuscated/padded? The existence of index blobs tells the host some information about the KV state. How much information leakage is acceptable here, and how much can we avoid by padding?*

In the current design these indexes are entirely node-local and never shared, so a node only needs to be able to decipher its own index files.
For simplicity, we aim to provide the same protections on all data rather than distinguishing public and private data at this stage.
While we consider this scheme further, only data from public tables will be indexed in this way, to avoid leakage of confidential data.

The intended high-level flow is as follows:

* A strategy produces a blob of data for the LFS system inside the enclave to store: ``store(name, data)``

* The LFS system generates an obfuscated name ``name'`` and encrypts the data ``data'``

* The LFS system passes ``name'`` and ``data'`` to the host

* Later, the strategy returns to the LFS system and requests that blob: ``fetch(name)``

* The LFS system generates ``name'``, and requests this from the host

* The host responds with some data ``D``

* The in-enclave LFS system verifies that ``D`` == ``data'``, decrypts to ``data``, and provides ``data`` to the caller

Clearly ``data`` must be encrypted and integrity protected to prevent trivial information reveal/tampering.
Additionally, both ``name`` and the size of ``data'`` may reveal some information about the contents.
We want the name obfuscation to limit the former, and will explore padding options for the latter.

The current details, and open questions, are:

* We expect ``name`` and ``data`` to always be a matching pair, once the LFS has seen it. So we are not appending incrementally different values of ``data`` each time, and even if we re-index in future we will produce identical values.

* A node generates a fresh AES-GCM key |K_LFS| on startup, which never leaves the enclave. This will be used to encrypt and decrypt all of its LFS files, and lives as long as the node.

   * Should this be derived from the node key?
   * *This should be rotated rather than used indefinitely! But does the derived key need to be determined from ``name``, or can it be specified by ``D``?*
   * Should this just be a HKDF derived key per-file (aka per-``name``)?

* To fetch, we need to produce ``name'`` from ``name``. So if we want to derive a salt to hash with, it must be derived from the secret key.

* ``data'`` is the AES-GCM encryption of ``data``, using |K_LFS| and a randomly selected IV.

   * The host could convince a node to re-index, potentially producing ``data_a'``, ``data_b'``, ``data_c'``, with different IVs but from the same plaintext ``data``. Is this a risk?

* How should we confirm that we've got the correct ``data_a``, and not some other (created by us) ``data_b``? Embed some fingerprint bytes in the IV, or prefix the encrypted message (currently doing the latter)?

.. note::

    The LFS system is currently only used by indexing strategies, but may be used for additional tasks in future to implement a framework-level memory cache.

.. |K_LFS| replace:: K :sub:`LFS`

Paged B+ tree indexes
---------------------

``ccf::indexing::strategies::SeqnosByKey_Paged<M>`` (``ccf/indexing/strategies/seqnos_by_key_paged.h``) is an opt-in alternative to ``SeqnosByKey_Bucketed<M>``.
Install it on the indexing subsystem as for other strategies; the existing bucketed implementation is unchanged and remains available for comparison.
The constructor accepts a map, node context, maximum encoded page bytes (default 4096), and cache budget in bytes (default 65536).
It also works inside ``ccf::indexing::LazyStrategy``.
Only public tables are supported; there is no restart persistence or node sharing.

Each strategy owns one B+ tree ordered lexicographically by ``(serialised key, transaction seqno)``.
Leaves pack entries from different keys into the same bounded pages.
Internal pages contain inclusive lower-bound separators and child references.
No empty sequence-range buckets or permanent in-memory directory entries per key are created.
The tree records writes, not values; like the existing strategies, it does not record removals from the target map.

Queries and updates
~~~~~~~~~~~~~~~~~~~

``get_write_txs_in_range(key, from, to)`` returns the complete, inclusive ``SeqNoCollection``, or ``nullopt`` if indexing has not reached ``to``, a required page or checkpoint is pending, the slow-query cursor is occupied, or the strategy has failed.
An inverted range throws ``std::invalid_argument``.
There is no cache-dependent range-width limit.
A resumable cursor retains its traversal frontier and accumulated results across retries, so scans larger than the cache (including with a zero-byte cache) make progress rather than repeatedly restarting.
Cached traversals advance synchronously, with a work quota of 128 pages per call; they only suspend for missing pages or the quota.
Decoded pages are reused without repeated parsing.

There is currently only one slow-query cursor per strategy, shared across callers requesting the same serialised key and range.
Independent queries can still complete through the recent-history and verified-result fast paths.
Other slow queries receive ``nullopt`` until the cursor's result is collected or it is cancelled.
Callers must retry the same query to collect its result, or call ``cancel_query()`` when abandoning it.
Cancellation drains any already-issued fetch before releasing the cursor, rather than accumulating abandoned I/O.
An incomplete cursor pauses mutation and reclamation and sees a consistent root.
One subsequent transaction may be retained while it finishes.
A completed cursor holds only its materialised result, so updates and reclamation can resume before that result is collected.
An abandoned incomplete cursor can still stall updates until it finishes or is explicitly cancelled.
As with all asynchronous LFS operations, a host that withholds I/O can deny progress.

Updates collect one transaction's serialised keys using the existing read-only ``foreach`` API, then sort that key-only buffer once before resumable tree insertion.
They do not retain the historical store or values, and require no changes to CHAMP, KV handles, public KV APIs, or KV tracing.
Only one transaction can be pending; the buffer is released on completion or failure.
Each insertion may suspend on an uncached page; ``next_requested()`` returns ``nullopt`` while that transaction is pending.
``tick()`` resumes processing, and the indexed watermark advances only after every key in the transaction has been incorporated into the trusted tree, which can include bounded unflushed pages.
New slow queries wait during a pending transaction; complete answers from trusted caches below the previous watermark remain valid.
No query can expose a partially incorporated transaction.
Key collection is linear, sorting is O(n log n), and the additional temporary buffer is O(transaction key bytes).
Collection and sorting happen synchronously in the transaction callback; the subsequent page processing is resumable.
This intentionally trades a per-transaction memory allocation for avoiding both quadratic rescanning and changes to the underlying KV.

Half the cache budget (when the total budget is at least 512 bytes) is reserved for a recent-history posting map with a trusted complete sequence interval.
Eviction drops a whole sequence prefix across all keys, not individual keys, so empty results within that interval are trustworthy.
A transaction too large to fit can advance the coverage floor past itself; queries then use the tree instead of receiving incomplete cached answers.
Complete historical results may also be retained in the shared byte-accounted LRU; their fixed ranges remain valid as later committed transactions append larger seqnos.
These caches are bounded and do not create a permanent directory entry per historical key.

Integrity and storage lifecycle
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pages receive monotonically increasing IDs within a randomly named strategy instance.
Copy-on-write replacements first live in a bounded trusted working tree; references to these unpublished pages resolve only through its in-memory page-ID directory, not host-provided data.
At a checkpoint their child references are sealed and hashed bottom-up before any pages are submitted to LFS.
Persisted pages are immutable: the root ID/hash remain in trusted memory and internal pages authenticate every persisted child's ID and hash.
LFS additionally encrypts each page and binds its ciphertext to its storage key.
Fetched plaintext is hashed against the trusted root/parent reference before it is decoded or contributes results.
Missing, corrupt, substituted, or stale required pages therefore cannot produce a successful incomplete result.
A page-integrity failure is logged and permanently disables this strategy's queries and progress; rebuilding requires removing and reinstalling the strategy and requesting the desired history again.

Copy-on-write insertions coalesce unpublished replacements across keys and transactions in the bounded working tree.
A checkpoint writes only its current reachable dirty pages and removes replaced persisted pages through one ordered LFS batch; superseded unpublished pages never reach disk.
The strategy allows at most one outstanding fetch or batch and applies backpressure while a checkpoint completes.
No query references removed pages.
Completion means the writes and removals have executed, not that data has been fsynced for crash recovery.
Batch I/O errors are logged and reported as failure, including abandonment on task shutdown.
Partially applied failed batches fail closed and may leave a bounded batch of orphan pages; this strategy never continues producing obsolete pages after failure.
Removing a strategy does not walk and erase its remaining live tree; those files remain until node startup clears the LFS directory.
The host can always ignore deletion, so physical reclamation is not an integrity guarantee.

On a cooperating filesystem, completed checkpoints leave only live pages, not an accumulating history of old roots.
Between checkpoints, dirty pages and a bounded list of obsolete persisted pages are retained.
The working-set target is ``max(cache_bytes, 8 * page_bytes)``; resident dirty-page charges plus obsolete encoded bytes trigger a checkpoint between insertions.
One insertion can overshoot that target by one bounded root-to-leaf rewrite/split burst, proportional to page size and height, rather than transaction size.
``flush()`` requests an asynchronous checkpoint; it does not add restart persistence or a durability guarantee.
LFS's optional per-fetch plaintext bound is enforced against the encrypted file size before allocating host-provided data, even when another strategy has previously stored larger blobs.
The existing unbounded ``store()`` API is unchanged; the bounded outstanding-work policy applies to this strategy, not all LFS clients globally.

Resource limits and measurements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``describe()`` reports live encoded page bytes and count (including dirty pages), height, shared-cache usage and peak, working-set usage and peak, obsolete page count, recent coverage floor, key visits, page decodes, pending transaction/batch status, query activity, and failure status.
``pending_key_buffer_bytes`` and ``key_buffer_peak_bytes`` account the temporary key-vector capacity and heap-backed key contents separately.
The shared query/update cache accounts decoded page capacities, posting/result capacities, hash buckets, container payloads/links, and modelled shared-pointer control storage; allocator bookkeeping is not included.
The dirty working set is a separate bounded budget, not part of ``cache_bytes``.
Shared ownership can make the conservative update-path charge overlap cache or working-set storage; these diagnostics are not process RSS.
Decoded path references, encryption/hash scratch, one recent-posting replacement candidate, and pending checkpoint bytes are additional bounded work.
``live_pages`` need not equal the host's file count until dirty work is checkpointed and obsolete files have been removed.
The height is capped at 64; page size must be between 512 bytes and 1 MiB.
For an internal entry to fit, a serialised key must satisfy ``key_bytes + 56 <= floor((page_bytes - 9) / 4)``.
Exceeding the key limit logs a failure and disables indexing without advancing the transaction watermark.
Choose page size to accommodate the application's largest serialised key.

The temporary key buffer and the materialised ``SeqNoCollection`` are not bounded by the cache budget.
In particular, a hot-key query may retain a result proportional to the requested history even with a zero-byte cache.
This API does not provide an end-to-end fixed memory bound, streaming results, or a bound on application key serialisation.

The ``indexing_test`` paged suite checks the following distributions over 1000 transactions using 512-byte pages and a 1024-byte cache (Debug, x86-64), explicitly checkpointing after each transaction.
These are deterministic regression measurements of managed structures, not process RSS or a throughput benchmark.
Update-path accounting includes vector capacities and key/reference storage but excludes allocator metadata.

.. list-table::
   :header-rows: 1

   * - Distribution
     - Entries
     - Live pages
     - Encoded bytes
     - Cache peak
     - Update path peak
     - Write batch peak
   * - One hot key
     - 1000
     - 103
     - 28149
     - 1024
     - 2264
     - 1848
   * - One write every 100 transactions
     - 10
     - 1
     - 249
     - 1008
     - 0
     - 249
   * - 1000 distinct keys
     - 1000
     - 132
     - 35834
     - 1024
     - 2360
     - 2035

Every distribution checks a peak queue length of one and verifies that the remaining stored files and bytes exactly equal the live tree after every transaction.
The encrypted-LFS integration test also checks real file count and length after repeated splits and reclamation.
Encrypted files add 100 bytes per page in the normal configuration (64-byte obfuscated key, 8-byte length, and 28-byte GCM header), before filesystem allocation and directory overhead.
Small stress-test pages can therefore be much less space-efficient on disk than the default 4096-byte pages.

Performance comparison
----------------------

The initial prototype measurements below motivated the cache and batching optimizations described in the final subsection.
Those optimizations bring default-cache recent/repeated-query timings near parity or better in the tested matrix, but the implementation is not yet a general concurrent drop-in replacement.
Random-update ingestion and very small caches still have material trade-offs.

Reproducing the comparison
~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``indexing_compare`` executable runs both strategies against identical serialised public-map transactions, a real ``Indexer``, and encrypted ``EnclaveLFSAccess`` files.
It checks every complete query result against a reference model and fails on incorrect results, I/O errors, rebuilds, or a phase exceeding 60 seconds.
The CTest smoke comparison also exercises range chunking and constrained caches.

.. code-block:: bash

   cmake -S . -B build.perf -GNinja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_TESTS=ON
   cmake --build build.perf --target indexing_compare --parallel "$(nproc)"
   ctest --test-dir build.perf -R '^indexing_compare$' --output-on-failure --no-tests=error
   build.perf/indexing_compare --entries 4096 --queries 16 --repetitions 3 \
     --output build.perf/comparison-default.json
   build.perf/indexing_compare --entries 4096 --queries 16 --repetitions 3 \
     --cache-bytes 4096 --bucket-cache 4 \
     --output build.perf/comparison-constrained.json
   build.perf/indexing_compare --entries 16384 --queries 16 --repetitions 3 \
     --workload distinct --output build.perf/comparison-distinct-16384.json
   build.perf/indexing_compare --entries 16384 --queries 16 --repetitions 3 \
     --workload batch-16384 --output build.perf/comparison-batch-16384.json

The executable creates and removes its own scratch directory under the system temporary directory; it does not clear an existing checkout's LFS directory.
Failed runs retain the printed scratch directory for diagnosis.
The JSON output contains raw latency samples, p50/p95/mean, API-call and chunk counts, read/write traffic, reclamation counts, peak I/O queue depth, allocated/encrypted file sizes, and strategy descriptions.
``--workload`` can select a single case; ``--help`` lists page, cache, bucket and sample settings.

Method and boundaries
~~~~~~~~~~~~~~~~~~~~~

These are in-process, end-to-end indexing-pipeline measurements, not node/network/HTTP benchmarks.
Consensus/signature verification, client polling delays, and ledger retrieval from disk are excluded.
Transaction creation/serialisation and reference-model construction happen before timing; replay deserialisation, indexing, LFS encryption/read/write/removal, queue draining, query retries, and complete result assembly are timed.
Queued asynchronous actions are pumped deterministically on the calling thread, without an artificial tick interval or parallel I/O worker.
Idle ``JobBoard::get_task()`` calls are avoided because their zero-duration condition-variable waits otherwise add unrelated scheduler delays to in-memory retries.
Neither filesystem caches nor CPU placement are controlled, and LFS completion does not include fsync.
There is no claim of cold-disk latency, production concurrency throughput, or statistical confidence beyond these exploratory samples.

Each strategy is rebuilt for each repetition, with execution order alternating between repetitions.
Each query's first pass follows index construction and earlier queries; its repeat immediately requests the same key and range.
The first pass is not necessarily a cache miss, particularly because the paged strategy shares its update and query cache.
Query-key selection follows the write-frequency distribution, except that the sparse case selects rare keys rather than its background key.
Missing-key queries alternate keys before, adjacent to, and after the populated key space.
Every query materialises the complete result, including aggregation across multiple bucketed calls when its range exceeds ``max_requestable_range()``.
This adapter is counted in the timing; a full-range query is never silently truncated to the bucketed API's maximum.

The default configurations are the production constructor defaults: 4096-byte pages with a 65536-byte paged cache, versus 1000-seqno buckets and 10 cached buckets.
These are not equal total-memory budgets: the bucketed strategy additionally retains a current result per key, while the paged budget excludes its temporary transaction-key buffer, result memory and bounded traversal work.
The constrained configuration reduces the paged cache to 4096 bytes and the bucketed cache to four buckets, not to an equivalent number of bytes.
Do not interpret the disk tables as a comparison of total memory or full durable-index size; current bucket tails and optimized paged working pages can remain in trusted RAM.

Measurements were taken on 2026-11-05 with Clang 18.1.8, ``RelWithDebInfo`` (``-O2``), an AMD EPYC 7763 host exposing 32 logical CPUs, and ext4 temporary storage.
The implementation was the worktree changes atop upstream commit ``9e5082345dc5d39343828baa382d27097aaca66e``.
Numbers are medians across three repetitions; query columns take the median of each repetition's sample percentile.
There are 16 first-pass and 16 repeat samples per pattern per repetition, so p95 is exploratory rather than a reliable service-tail estimate.
Hardware counter profiling was unavailable because ``perf_event_paranoid=4``; the comparison uses steady-clock elapsed time and explicit I/O counters.

Workloads and ingestion
~~~~~~~~~~~~~~~~~~~~~~~

``hot`` writes one key in every transaction.
``uniform`` chooses among 256 keys.
``skewed`` directs 90 percent of writes to 16 hot keys and the remainder to 1024 other possible keys.
``sparse`` writes a rare key every 128 transactions, cycling through 16 rare keys, and otherwise writes one background key.
``distinct`` introduces a new key in every transaction, including late arrivals which require empty historical buckets in the bucketed strategy.
The ``batch-*`` cases group the same 4096 distinct-key entries into successively wider transactions.

.. csv-table:: Initial indexing time, milliseconds (lower is better)
   :header: "Workload", "Keys per transaction", "Bucketed", "Paged"

   "Hot", 1, 24.27, 823.78
   "Uniform", 1, 70.89, 832.35
   "Skewed", 1, 58.40, 842.49
   "Sparse plus background", 1, 28.00, 835.46
   "Distinct", 1, 326.64, 853.98
   "Batch 8", 8, 3.88, 813.22
   "Batch 64", 64, 2.21, 811.08
   "Batch 512", 512, 2.29, 848.13
   "Batch 4096", 4096, 2.84, 1197.42

At 16384 total entries, one distinct key per transaction took 5514.76 ms bucketed versus 4601.75 ms paged.
Here the bucketed empty-file cost overtakes COW update costs.
In contrast, one transaction containing all 16384 keys took 12.96 ms bucketed versus 11537.04 ms paged.
Increasing that single transaction from 4096 to 16384 keys multiplies paged time by about 9.6 for four times the entries.
The large-transaction regression is real, not merely an asymptotic warning.
These timings include other costs and do not isolate rescanning CPU time, but the per-transaction repeated map scans and per-entry COW I/O both need addressing before recommending bulk ingestion.

The I/O counters expose a separate problem even without large transactions: the 4096-entry hot case writes 8038 pages containing 17.56 MB of plaintext and reads 7996 pages, versus four bucket files containing 32.02 KB of plaintext.
Each COW insertion rewrites its path, and subsequent updates reload the new pages rather than retaining decoded mutable working pages.
Avoiding quadratic key selection alone will not close this write/read-amplification gap.

Query latency
~~~~~~~~~~~~~

Recent and historical-window queries span at most 64 transaction seqnos; full-history queries cover all 4096 initial transactions.
Some selected keys have no writes in a narrow window; those complete empty results are checked too.
The following values are p50 in microseconds, including all retries and result assembly.

.. csv-table:: Default-cache query latency (lower is better)
   :header: "Workload / query", "Bucket first", "Paged first", "Bucket repeat", "Paged repeat"

   "Hot / recent", 0.88, 10.04, 0.87, 10.05
   "Hot / full history", 35.96, 1087.44, 35.97, 1085.11
   "Uniform / recent", 0.30, 31.57, 0.24, 7.40
   "Uniform / historical window", 22.51, 29.79, 0.33, 6.96
   "Uniform / full history", 63.38, 31.01, 1.17, 7.23
   "Skewed / full history", 89.64, 70.29, 6.44, 22.31
   "Sparse / historical window", 21.46, 5.60, 0.27, 5.60
   "Sparse / full history", 40.68, 5.84, 0.66, 5.75
   "Distinct / full history", 25.35, 28.87, 0.55, 5.22
   "Distinct / missing keys", 0.32, 5.47, 0.27, 5.29

.. csv-table:: First-pass full-history p95, microseconds
   :header: "Workload", "Bucketed", "Paged"

   "Hot", 136.45, 1180.19
   "Uniform", 83.95, 42.18
   "Skewed", 116.68, 123.48
   "Sparse", 65.10, 9.92
   "Distinct", 69.42, 45.64

The paged strategy wins some first-pass history queries, particularly sparse keys, but loses the immediate repeat and recent-query cases in this matrix.
The hot full scan is larger than the paged cache and continues reading pages on repeat; the bucketed cache can retain its much smaller seqno-only representation.
With the constrained caches, first-pass full-history p50 changes to 62.39/51.63 microseconds (bucketed/paged) for uniform keys, 89.31/130.79 for skewed keys, 44.87/47.81 for sparse keys, and 42.71/66.05 for distinct keys.
The bucketed adapter makes two range calls instead of one, while the paged traversal still completes with its smaller cache; progress is preserved, but most of the first-pass advantage disappears.

At 16384 distinct keys the full-history first-pass p50 is 124.48 microseconds bucketed versus 31.60 paged, and p95 is 321.23 versus 51.58.
That query requires two bucketed range chunks versus one paged call sequence.
Repeating it remains faster bucketed: 1.11 versus 6.20 microseconds.

After the query phase, each run appends another one-eighth of the entries in groups of at most 16 transactions while retrying a query against the previous watermark.
This mixed phase includes the time to finish both the query and indexing catch-up, not just the query's service time.
For the 4096-entry hot/uniform/skewed/sparse/distinct cases, total mixed-phase milliseconds are respectively 2.93/147.18, 12.80/109.78, 11.52/112.71, 3.14/110.41, and 90.54/147.90 (bucketed/paged).
This serial-client test exercises query/update interaction but is not a multi-client fairness or throughput benchmark.

Storage and recommendation
~~~~~~~~~~~~~~~~~~~~~~~~~~

The physical-allocation figures below sum regular-file ``st_blocks * 512``; directory and inode overhead are additional.
All figures are captured after initial indexing, before query and mixed-update phases.

.. csv-table:: Live file count and allocated file bytes
   :header: "Data set", "Bucket files", "Paged files", "Bucket allocated bytes", "Paged allocated bytes"

   "4096 hot writes", 4, 42, 32768, 172032
   "4096 uniform writes", 844, 41, 3457024, 180224
   "4096 skewed writes", 695, 51, 2846720, 212992
   "4096 sparse/background writes", 44, 47, 196608, 192512
   "4096 distinct keys", 6388, 62, 26165248, 253952
   "16384 distinct keys", 126160, 245, 516751360, 1007616

The high-cardinality benefit is substantial: at 16384 distinct keys, paged live encrypted contents occupy 535305 bytes versus 13625280 bytes for bucketed files, and regular-file allocation drops by roughly 513 times.
The bucketed index additionally retains 16384 current key results in RAM; there is no corresponding permanent paged key directory.
However, for hot keys the paged representation consumes more disk and performs far more I/O.

These initial measurements did not establish that paged indexing was better for most common applications.
The following optimization iteration addresses their common-query and quadratic-selection costs without increasing the configured cache budget.

Optimized cache and batching results
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The same paired comparisons were rerun with decoded-page caching, synchronous cached traversals, indexing-local key collection/sorting, bounded coalesced COW checkpoints, complete recent-history coverage, and verified historical-result caching.
These measurements supersede the intermediate cursor-based optimization: all underlying KV/CHAMP implementation, API and test files are unchanged from the baseline.
The configurations, input sizes, repetitions, result checks and timing boundaries are unchanged.
The paged working set is now allowed to remain in trusted RAM at transaction boundaries, analogously to bucketed current tails; the build timer still waits for any submitted checkpoint's completion.
The following p50/p95 values are microseconds for immediate repeat queries with the default cache.

.. csv-table:: Optimized repeated-query latency
   :header: "Workload / query", "Bucket p50", "Paged p50", "Bucket p95", "Paged p95"

   "Hot / recent", 0.911, 0.511, 1.112, 0.742
   "Uniform / recent", 0.231, 0.221, 0.430, 0.361
   "Skewed / recent", 0.320, 0.300, 0.592, 0.611
   "Sparse / recent", 0.220, 0.201, 0.391, 0.360
   "Distinct / recent", 0.221, 0.200, 0.491, 0.350
   "Hot / full history", 37.179, 17.953, 37.450, 30.637
   "Uniform / full history", 1.122, 0.501, 1.593, 0.702
   "Skewed / full history", 6.542, 3.106, 7.243, 3.547
   "Sparse / full history", 0.641, 0.280, 0.772, 0.321
   "Distinct / full history", 0.552, 0.250, 0.691, 0.291

Recent-query first-pass p50 is also comparable or better in the default-cache matrix: bucketed/paged values are 0.902/0.501 (hot), 0.291/0.281 (uniform), 0.411/0.351 (skewed), 0.230/0.230 (sparse), and 0.461/0.211 (distinct).
This is not a guarantee of cold-disk performance or concurrency fairness.

.. csv-table:: Initial indexing time after optimization, milliseconds
   :header: "Workload", "Bucketed", "Paged"

   "4096 hot writes", 23.38, 34.84
   "4096 uniform writes", 69.62, 294.62
   "4096 skewed writes", 57.04, 283.00
   "4096 sparse/background writes", 25.38, 34.09
   "4096 distinct keys", 329.70, 38.50
   "One transaction, 4096 keys", 2.79, 13.13
   "16384 distinct keys", 5411.60, 163.31
   "One transaction, 16384 keys", 12.96, 63.02

The 16384-key transaction improves from 11537 ms in the initial prototype to 63 ms, with exactly 16384 keys collected by one ``foreach`` rather than repeated full-map scans.
Sorting all keys once also avoids the unordered chunk revisits of the discarded cursor-based iteration.
It is still about five times slower than bucketed ingestion in this case; checkpointing and tree-maintenance work remain.
The 16384-distinct-key case writes 353 pages and reads no LFS pages while building, instead of the original 45189 writes and 44944 reads.
Its median build time is 163 ms versus 5412 ms bucketed; individual paged repetitions were 163, 159 and 170 ms on the shared machine.

Hot-key write amplification is substantially reduced: 4096 writes now submit 55 pages containing 113835 plaintext bytes and perform no LFS reads during indexing, instead of 8038 writes containing 17.56 MB and 7996 reads.
Random uniform/skewed updates remain roughly four to five times slower to index than bucketed in this small data set, despite the improved query fast paths.
They still incur checkpoint and leaf-read traffic when their working set does not fit.

In the constrained 4096-byte cache, repeated recent-query p50 remains comparable in this matrix, but first-pass uniform/skewed/distinct recent queries can still require disk reads and take 26 to 46 microseconds.
Repeated skewed full-history queries can take 96 microseconds versus 6.51 bucketed because their verified results exceed the admission budget and their pages do not fit.
These are real remaining regressions, not hidden by increasing cache size.

The optimized 16384-distinct-key run has 245 host files with 1007616 allocated bytes, versus 126160 files and 516751360 bytes bucketed.
It also retains three dirty pages and three obsolete-page records before a final explicit checkpoint; host files alone are not the complete paged working state.
The shared cache stays within 65536 bytes, and observed working-set peaks are about 67 to 68 KB, including the bounded insertion overshoot.
The key-only buffer peaks at 98304 bytes for the 4096-key transaction and 393216 bytes for the 16384-key transaction with these short serialised keys, then drops to zero on completion.
Longer keys can require more memory.
The strategy does not retain the historical store or its values across asynchronous processing, but the temporary key buffer has no fixed per-transaction byte limit.
The working set, temporary key buffer, transient scratch, and materialised caller results are not all covered by the cache budget.

The optimization meets recent/repeated-query parity in the tested default-cache serial-client matrix, not the broader drop-in-replacement goal.
The single incomplete slow cursor still serializes mutation and other slow queries, even though completed cursors no longer block writers and trusted fast-path queries can proceed independently.
Removing that restriction with bounded fair concurrent cursors and safe snapshot reclamation, followed by network-level load tests using application traces, remains necessary before claiming concurrent replacement suitability.