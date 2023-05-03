// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ccf_assert.h"
#include "ccf/ds/logger.h"
#include "ccf/pal/locking.h"
#include "consensus/ledger_enclave_types.h"
#include "ds/thread_messaging.h"
#include "kv/kv_types.h"
#include "kv/store.h"
#include "node/network_state.h"
#include "node/snapshot_serdes.h"
#include "service/tables/snapshot_evidence.h"

#include <deque>
#include <optional>

namespace ccf
{
  class Snapshotter : public std::enable_shared_from_this<Snapshotter>,
                      public kv::AbstractSnapshotter
  {
  public:
    static constexpr auto max_tx_interval = std::numeric_limits<size_t>::max();

  private:
    ringbuffer::AbstractWriterFactory& writer_factory;

    ccf::pal::Mutex lock;

    std::shared_ptr<kv::Store> store;

    // Snapshots are never generated by default (e.g. during public recovery)
    size_t snapshot_tx_interval = max_tx_interval;

    struct SnapshotInfo
    {
      crypto::Sha256Hash write_set_digest;
      std::string commit_evidence;
      crypto::Sha256Hash snapshot_digest;

      std::optional<consensus::Index> evidence_idx = std::nullopt;

      std::optional<NodeId> node_id = std::nullopt;
      std::optional<crypto::Pem> node_cert = std::nullopt;
      std::optional<std::vector<uint8_t>> sig = std::nullopt;
      std::optional<std::vector<uint8_t>> tree = std::nullopt;

      SnapshotInfo() = default;
    };
    // Queue of pending snapshots that have been generated, but are not yet
    // committed
    std::map<consensus::Index, SnapshotInfo> pending_snapshots;

    struct OtherSnapshotInfo
    {};
    std::map<size_t, OtherSnapshotInfo> in_progress_snapshots;

    // Initial snapshot index
    static constexpr consensus::Index initial_snapshot_idx = 0;

    // Index at which the latest snapshot was generated
    consensus::Index last_snapshot_idx = 0;

    // Used to suspend snapshot generation during public recovery
    bool snapshot_generation_enabled = true;

    // Indices at which a snapshot will be next generated and Boolean to
    // indicate whether a snapshot was forced at the given index
    struct SnapshotEntry
    {
      consensus::Index idx;
      bool forced;
      bool done;
    };
    std::deque<SnapshotEntry> next_snapshot_indices;

    void record_snapshot(
      consensus::Index idx,
      consensus::Index evidence_idx,
      const std::vector<uint8_t>& serialised_snapshot)
    {
      auto to_host = writer_factory.create_writer_to_outside();
      size_t max_message_size = to_host->get_max_message_size();
      if (serialised_snapshot.size() > max_message_size)
      {
        LOG_FAIL_FMT(
          "Could not write snapshot of size {} > max ring buffer msg size {}",
          serialised_snapshot.size(),
          max_message_size);
        return;
      }
      RINGBUFFER_WRITE_MESSAGE(
        consensus::snapshot, to_host, idx, evidence_idx, serialised_snapshot);
    }

    void commit_snapshot(
      consensus::Index snapshot_idx,
      const std::vector<uint8_t>& serialised_receipt)
    {
      // The snapshot_idx is used to retrieve the correct snapshot file
      // previously generated.
      auto to_host = writer_factory.create_writer_to_outside();
      RINGBUFFER_WRITE_MESSAGE(
        consensus::snapshot_commit, to_host, snapshot_idx, serialised_receipt);
    }

    struct SnapshotMsg
    {
      std::shared_ptr<Snapshotter> self;
      std::unique_ptr<kv::AbstractStore::AbstractSnapshot> snapshot;
      std::vector<uint8_t> serialised_snapshot;
    };

    static void snapshot_cb(std::unique_ptr<threading::Tmsg<SnapshotMsg>> msg)
    {
      msg->data.self->snapshot_(std::move(msg->data.snapshot));
    }

    void snapshot_(
      std::unique_ptr<kv::AbstractStore::AbstractSnapshot> snapshot)
    {
      auto snapshot_version = snapshot->get_version();

      auto serialised_snapshot = store->serialise_snapshot(std::move(snapshot));

      LOG_FAIL_FMT(
        "Confirmed snapshot allocate size: {}", serialised_snapshot.size());

      auto tx = store->create_tx();
      auto evidence = tx.rw<SnapshotEvidence>(Tables::SNAPSHOT_EVIDENCE);
      auto snapshot_hash = crypto::Sha256Hash(serialised_snapshot);
      evidence->put({snapshot_hash, snapshot_version});

      ccf::ClaimsDigest cd;
      cd.set(std::move(snapshot_hash));

      crypto::Sha256Hash ws_digest;
      std::string commit_evidence;
      auto capture_ws_digest_and_commit_evidence =
        [&ws_digest, &commit_evidence](
          const std::vector<uint8_t>& write_set,
          const std::string& commit_evidence_) {
          new (&ws_digest)
            crypto::Sha256Hash({write_set.data(), write_set.size()});
          commit_evidence = commit_evidence_;
        };

      // It is possible that the signature following the snapshot evidence is
      // scheduled by another thread while the below snapshot evidence
      // transaction is committed. To allow for such scenario, the evidence
      // seqno is recorded via `record_snapshot_evidence_idx()` on a hook rather
      // than here.
      pending_snapshots[snapshot_version] = {};

      auto rc =
        tx.commit(cd, false, nullptr, capture_ws_digest_and_commit_evidence);
      if (rc != kv::CommitResult::SUCCESS)
      {
        LOG_FAIL_FMT(
          "Could not commit snapshot evidence for seqno {}: {}",
          snapshot_version,
          rc);
        return;
      }

      pending_snapshots[snapshot_version].commit_evidence = commit_evidence;
      pending_snapshots[snapshot_version].write_set_digest = ws_digest;
      pending_snapshots[snapshot_version].snapshot_digest = cd.value();

      auto evidence_version = tx.commit_version();

      record_snapshot(snapshot_version, evidence_version, serialised_snapshot);

      LOG_DEBUG_FMT(
        "Snapshot successfully generated for seqno {}, with evidence seqno {}: "
        "{}, ws digest: {}",
        snapshot_version,
        evidence_version,
        cd.value(),
        ws_digest);
    }

    void update_indices(consensus::Index idx)
    {
      while ((next_snapshot_indices.size() > 1) &&
             (std::next(next_snapshot_indices.begin())->idx <= idx))
      {
        next_snapshot_indices.pop_front();
      }

      for (auto it = pending_snapshots.begin(); it != pending_snapshots.end();)
      {
        auto& snapshot_idx = it->first;
        auto& snapshot_info = it->second;

        if (
          snapshot_info.evidence_idx.has_value() &&
          idx > snapshot_info.evidence_idx.value())
        {
          auto serialised_receipt = build_and_serialise_receipt(
            snapshot_info.sig.value(),
            snapshot_info.tree.value(),
            snapshot_info.node_id.value(),
            snapshot_info.node_cert.value(),
            snapshot_info.evidence_idx.value(),
            snapshot_info.write_set_digest,
            snapshot_info.commit_evidence,
            std::move(snapshot_info.snapshot_digest));

          commit_snapshot(snapshot_idx, serialised_receipt);
          it = pending_snapshots.erase(it);
        }
        else
        {
          ++it;
        }
      }
    }

  public:
    Snapshotter(
      ringbuffer::AbstractWriterFactory& writer_factory_,
      std::shared_ptr<kv::Store>& store_,
      size_t snapshot_tx_interval_) :
      writer_factory(writer_factory_),
      store(store_),
      snapshot_tx_interval(snapshot_tx_interval_)
    {
      next_snapshot_indices.push_back({initial_snapshot_idx, false, true});
    }

    void init_after_public_recovery()
    {
      // After public recovery, the first node should have restored all
      // snapshot indices in next_snapshot_indices so that snapshot
      // generation can continue at the correct interval
      std::lock_guard<ccf::pal::Mutex> guard(lock);

      last_snapshot_idx = next_snapshot_indices.back().idx;
    }

    void set_snapshot_generation(bool enabled)
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      snapshot_generation_enabled = enabled;
    }

    void set_last_snapshot_idx(consensus::Index idx)
    {
      // Should only be called once, after a snapshot has been applied
      std::lock_guard<ccf::pal::Mutex> guard(lock);

      if (last_snapshot_idx != 0)
      {
        throw std::logic_error(
          "Last snapshot index can only be set if no snapshot has been "
          "generated");
      }

      last_snapshot_idx = idx;

      next_snapshot_indices.clear();
      next_snapshot_indices.push_back({last_snapshot_idx, false, true});
    }

    void store_snapshot(uint8_t* snapshot_buf, size_t request_id) const
    {
      LOG_FAIL_FMT("store_snapshot: {}", request_id);

      // TODO:
      // 0. Store serialised snapshot + snapshot version in map (key:
      // request_id)
      // 1. Retrieve snapshot from request_id
      // 2. Call snapshot_()

      std::memcpy(snapshot_buf, );
    }

    bool record_committable(consensus::Index idx) override
    {
      // Returns true if the committable idx will require the generation of a
      // snapshot, and thus a new ledger chunk
      std::lock_guard<ccf::pal::Mutex> guard(lock);

      CCF_ASSERT_FMT(
        idx >= next_snapshot_indices.back().idx,
        "Committable seqno {} < next snapshot seqno {}",
        idx,
        next_snapshot_indices.back().idx);

      bool forced = store->flag_enabled_unsafe(
        kv::AbstractStore::Flag::SNAPSHOT_AT_NEXT_SIGNATURE);

      consensus::Index last_unforced_idx = last_snapshot_idx;
      for (auto it = next_snapshot_indices.rbegin();
           it != next_snapshot_indices.rend();
           it++)
      {
        if (!it->forced)
        {
          last_unforced_idx = it->idx;
          break;
        }
      }

      auto due = (idx - last_unforced_idx) >= snapshot_tx_interval;
      if (due || forced)
      {
        next_snapshot_indices.push_back({idx, !due, false});
        LOG_TRACE_FMT(
          "{} {} as snapshot index", !due ? "Forced" : "Recorded", idx);
        store->unset_flag_unsafe(
          kv::AbstractStore::Flag::SNAPSHOT_AT_NEXT_SIGNATURE);
        return due;
      }

      return false;
    }

    void record_signature(
      consensus::Index idx,
      const std::vector<uint8_t>& sig,
      const NodeId& node_id,
      const crypto::Pem& node_cert)
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);

      for (auto& [snapshot_idx, pending_snapshot] : pending_snapshots)
      {
        if (
          pending_snapshot.evidence_idx.has_value() &&
          idx > pending_snapshot.evidence_idx.value() &&
          !pending_snapshot.sig.has_value())
        {
          LOG_TRACE_FMT(
            "Recording signature at {} for snapshot {} with evidence at {}",
            idx,
            snapshot_idx,
            pending_snapshot.evidence_idx.value());

          pending_snapshot.node_id = node_id;
          pending_snapshot.node_cert = node_cert;
          pending_snapshot.sig = sig;
        }
      }
    }

    void record_serialised_tree(
      consensus::Index idx, const std::vector<uint8_t>& tree)
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);

      for (auto& [snapshot_idx, pending_snapshot] : pending_snapshots)
      {
        if (
          pending_snapshot.evidence_idx.has_value() &&
          idx > pending_snapshot.evidence_idx.value() &&
          !pending_snapshot.tree.has_value())
        {
          LOG_TRACE_FMT(
            "Recording serialised tree at {} for snapshot {} with evidence at "
            "{}",
            idx,
            snapshot_idx,
            pending_snapshot.evidence_idx.value());

          pending_snapshot.tree = tree;
        }
      }
    }

    void record_snapshot_evidence_idx(
      consensus::Index idx, const SnapshotHash& snapshot)
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);

      for (auto& [snapshot_idx, pending_snapshot] : pending_snapshots)
      {
        if (snapshot_idx == snapshot.version)
        {
          LOG_TRACE_FMT(
            "Recording evidence idx at {} for snapshot {}", idx, snapshot_idx);

          pending_snapshot.evidence_idx = idx;
        }
      }
    }

    void schedule_snapshot(consensus::Index idx)
    {
      auto msg = std::make_unique<threading::Tmsg<SnapshotMsg>>(&snapshot_cb);
      msg->data.self = shared_from_this();
      msg->data.snapshot = store->snapshot_unsafe_maps(idx);
      msg->data.serialised_snapshot =
        store->serialise_snapshot(store->snapshot_unsafe_maps(idx));

      // TODO: Store elsewhere
      static size_t request_id = 0;

      auto const snapshot_size = msg->data.serialised_snapshot.size();
      LOG_FAIL_FMT("Snapshot allocate size: {}", snapshot_size);

      auto to_host = writer_factory.create_writer_to_outside();
      RINGBUFFER_WRITE_MESSAGE(
        consensus::snapshot_allocate, to_host, snapshot_size, request_id++);

      static uint32_t generation_count = 0;
      auto& tm = threading::ThreadMessaging::instance();
      tm.add_task(tm.get_execution_thread(generation_count++), std::move(msg));
    }

    void commit(consensus::Index idx, bool generate_snapshot) override
    {
      // If generate_snapshot is true, takes a snapshot of the key value store
      // at the last snapshottable index before idx, and schedule snapshot
      // serialisation on another thread (round-robin). Otherwise, only record
      // that a snapshot was generated.

      kv::ScopedStoreMapsLock maps_lock(store);
      std::lock_guard<ccf::pal::Mutex> guard(lock);

      update_indices(idx);

      if (idx < last_snapshot_idx)
      {
        throw std::logic_error(fmt::format(
          "Cannot snapshot at seqno {} which is earlier than last snapshot "
          "seqno {}",
          idx,
          last_snapshot_idx));
      }

      CCF_ASSERT_FMT(
        idx >= next_snapshot_indices.front().idx,
        "Cannot commit snapshotter at {}, which is before last snapshottable "
        "idx {}",
        idx,
        next_snapshot_indices.front().idx);

      auto& next = next_snapshot_indices.front();
      auto due = next.idx - last_snapshot_idx >= snapshot_tx_interval;
      if (due || (next.forced && !next.done))
      {
        if (snapshot_generation_enabled && generate_snapshot && next.idx)
        {
          schedule_snapshot(next.idx);
          next.done = true;
        }

        if (due && !next.forced)
        {
          // last_snapshot_idx records the last normally scheduled, i.e.
          // unforced, snapshot index, so that backups (which don't know forced
          // indices) continue the snapshot interval normally.
          last_snapshot_idx = next.idx;
          LOG_TRACE_FMT(
            "Recorded {} as last snapshot index", last_snapshot_idx);
        }
      }
    }

    void rollback(consensus::Index idx) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);

      while (!next_snapshot_indices.empty() &&
             (next_snapshot_indices.back().idx > idx))
      {
        next_snapshot_indices.pop_back();
      }

      if (next_snapshot_indices.empty())
      {
        next_snapshot_indices.push_back({last_snapshot_idx, false, true});
      }

      LOG_TRACE_FMT(
        "Rolled back snapshotter: last snapshottable idx is now {}",
        next_snapshot_indices.front().idx);

      while (!pending_snapshots.empty())
      {
        const auto& last_snapshot = std::prev(pending_snapshots.end());
        if (
          last_snapshot->second.evidence_idx.has_value() &&
          idx >= last_snapshot->second.evidence_idx.value())
        {
          break;
        }

        pending_snapshots.erase(last_snapshot);
      }
    }
  };
}
