Resource Usage
==============

CPU
---

A single CCF node process runs a host event-loop thread, an enclave dispatch thread, and worker threads, along with auxiliary threads. The host manages sockets and files, and handles communication with the enclave via ring-buffers.
The enclave dispatch thread handles incoming messages, while worker threads execute tasks including TLS termination, cryptography, and application and key value code.
The ``worker_threads`` configuration entry (see :ref:`operations/configuration:``worker_threads```) defaults to ``1``. CCF starts one more worker than configured, in addition to the dispatch thread, to preserve task execution capacity. For example, ``1`` starts two workers and ``2`` starts three. A configured value of ``0`` starts one worker and logs a warning; positive values are incremented silently.

Memory
------

The memory available to a CCF node process is ultimately bounded by the environment it runs in, typically the size of the virtual machine (VM) or container, and any additional OS- or container-level limits applied to the process.
On SEV-SNP, the node process runs inside a confidential VM; the VM size chosen at deployment time sets an upper bound on the memory that can be made available to the node, subject to any further limits imposed by the guest OS or container.

.. note:: If a JavaScript application is deployed, then by default the source code is pre-compiled into bytecode and stored in the Key Value store. While this reduces RPC latency it increases memory usage. The size of the bytecode cache can be queried via the ``/node/js_metrics`` RPC. See the :ref:`JavaScript Deployment <build_apps/js_app_bundle:Deployment>` section for details on enabling or disabling the cache.

Backpressure
------------

A node returns ``503 TooManyPendingTransactions`` for application and governance requests when either its local uncommitted transaction count reaches ``consensus.max_uncommitted_tx_count``, or its pending ledger append bytes reach ``memory.circuit_size`` (16MB by default). This applies to reads and writes on both primaries and backups. ``/node`` endpoints remain exempt so operators can diagnose a node that is not making progress. Setting ``consensus.max_uncommitted_tx_count`` to ``0`` disables only the transaction-count threshold, not ledger backpressure.

While its ledger is backlogged, a node also drops incoming AppendEntries replication messages, including heartbeats, without applying them or replying. Normal periodic probes and retransmissions allow it to catch up once ledger IO clears the backlog. Long IO stalls may cause elections or interrupt service if too few nodes can keep up. Ledger backlog threshold crossings are logged; persistent overload warrants investigating storage latency and node resource contention.

These are admission thresholds, not hard memory caps. Already-admitted work and internal operations can continue, and ``/node``-triggered writes are not capped by this gate. Requests are admitted again when both conditions clear. Completion of a ledger append is not a new per-transaction disk synchronisation guarantee; see :doc:`ledger_snapshot` for ledger file persistence and management.
