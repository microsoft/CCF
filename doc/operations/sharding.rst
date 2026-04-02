Temporal Sharding
=================

Temporal sharding allows operators to seal completed time ranges of the ledger into immutable, independently-addressable shards. The active shard continues accepting writes while sealed shards are automatically archived to the shared read-only ledger directory for access by all nodes.

Sharding is disabled by default and has no effect on existing single-shard behaviour.

Concepts
--------

**Shard**
  A contiguous range of ledger sequence numbers. At any time, exactly one shard is *active* (accepting writes). Older shards progress through *Sealing* and *Sealed* states.

**Shard seal**
  The process of closing the active shard at a committed sequence number, triggering a snapshot at the boundary, rekeying the ledger secret, and opening a new active shard.

**Shard policy**
  Governance-controlled thresholds that may trigger automatic sealing based on sequence number count or elapsed time.

Prerequisites
-------------

Sharding requires at least one entry in ``ledger.read_only_directories``. This is the shared mount path (e.g. a Kubernetes PVC) where all nodes look for committed ledger chunks. When a shard is sealed, its ledger chunks are hard-linked (or copied) into ``<first read_only_directory>/shards/<shard_id>/``, making sealed shard data automatically available to all nodes mounting the same volume.

If ``ledger.read_only_directories`` is empty when sharding is enabled, the node logs an error and sharding is not activated.

Configuration
-------------

Sharding is configured in the node's JSON configuration file:

.. code-block:: json

    {
      "ledger": {
        "directory": "ledger",
        "read_only_directories": ["/shared/ledger"]
      },
      "sharding": {
        "enabled": true,
        "auto_seal_after_seqno_count": 100000,
        "auto_seal_after_duration_s": 3600,
        "max_active_shard_memory_mb": 1024
      }
    }

.. list-table::
   :header-rows: 1
   :widths: 35 10 55

   * - Field
     - Default
     - Description
   * - ``enabled``
     - ``false``
     - Enable temporal sharding.
   * - ``auto_seal_after_seqno_count``
     - ``0``
     - Automatically seal the active shard after this many committed sequence numbers. ``0`` disables auto-seal by count.
   * - ``auto_seal_after_duration_s``
     - ``0``
     - Automatically seal the active shard after this many seconds. ``0`` disables auto-seal by time.
   * - ``max_active_shard_memory_mb``
     - ``0``
     - Advisory memory limit for the active shard. ``0`` means unlimited.

When sharding is enabled, the initial shard (shard 0) is created automatically when the service transitions to open.

Governance Actions
------------------

Members can manage shards through governance proposals.

``seal_current_shard``
~~~~~~~~~~~~~~~~~~~~~~

Seals the currently active shard at the latest committed sequence number. This initiates a two-phase process: the shard is marked as **Sealing**, a snapshot is triggered at the boundary, and the ledger is rekeyed. Once the snapshot is committed asynchronously, the shard transitions to **Sealed** and its data is archived to the shared read-only ledger directory.

.. code-block:: json

    {
      "actions": [
        {
          "name": "seal_current_shard"
        }
      ]
    }

``set_shard_policy``
~~~~~~~~~~~~~~~~~~~~

Updates the shard policy. All fields are optional — unspecified fields default to ``0`` (disabled).

.. code-block:: json

    {
      "actions": [
        {
          "name": "set_shard_policy",
          "args": {
            "auto_seal_after_seqno_count": 100000,
            "auto_seal_after_duration_s": 3600,
            "max_active_shard_memory_mb": 1024
          }
        }
      ]
    }

``migrate_shard`` has been removed — sealed shards are automatically archived to the first ``ledger.read_only_directories`` entry.

KV Tables
---------

Shard metadata is stored in public governance tables:

- ``public:ccf.gov.shards.info`` — Maps shard ID to ``ShardInfo`` (shard boundaries, status, snapshot seqno).
- ``public:ccf.gov.shards.policy`` — Singleton ``ShardPolicyInfo`` (auto-seal thresholds).

Sealed Shard Storage
--------------------

When a shard is sealed, the primary node sends a ``ledger_shard_sealed`` message to the host process. The host hard-links (or copies, if cross-device) all committed ledger chunk files covering the shard's sequence number range from ``ledger.directory`` into:

.. code-block:: text

    <first read_only_directory>/shards/<shard_id>/

This means all nodes mounting the same shared volume automatically have access to sealed shard data for historical queries, without requiring explicit migration.

Shard Lifecycle
---------------

1. **Active** — The shard is open and accepting writes.
2. **Sealing** — A seal has been initiated. A snapshot is being taken at the shard boundary and the ledger is being rekeyed. The shard remains in this state until the snapshot is committed.
3. **Sealed** — The snapshot has been committed. The shard is immutable and its data has been archived to the shared read-only directory.

.. code-block:: text

    Active ──seal_current_shard──> Sealing ──snapshot committed (async)──> Sealed

The transition from Sealing to Sealed is **asynchronous**: when the snapshotter commits the shard-seal snapshot, it fires a callback (``on_shard_seal_committed``) that updates the shard status in the KV and notifies the host to archive the ledger chunks. This ensures that sealed shard data is only archived after the boundary snapshot is durable.

Auto-seal
---------

When ``auto_seal_after_seqno_count`` or ``auto_seal_after_duration_s`` is configured and sharding is enabled, the primary node periodically checks these thresholds. If either threshold is exceeded, the active shard is sealed automatically without requiring a governance proposal.

Recovery
--------

During service recovery, the sharding state is restored from the KV store. The node identifies the current active shard and resumes from its start sequence number. Ledger secret chains are preserved across shard boundaries via the existing encrypted past ledger secret mechanism.

If a shard is found in the **Sealing** state during recovery (i.e. the node crashed after initiating a seal but before the snapshot was committed), the seal can be retried via a new ``seal_current_shard`` proposal once the service is open.
