// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ccf_assert.h"
#include "ccf/ds/logger.h"
#include "ccf/pal/enclave.h"
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
  private:
    static constexpr auto max_tx_interval = std::numeric_limits<size_t>::max();

    // Maximum number of pending snapshots allowed at a given time. No more
    // snapshots are emitted when this threshold is reached and until pending
    // snapshots are flushed on commit.
    static constexpr auto max_pending_snapshots_count = 5;

    ringbuffer::AbstractWriterFactory& writer_factory;

    ccf::pal::Mutex lock;

    std::shared_ptr<kv::Store> store;

    // Snapshots are never generated by default (e.g. during public recovery)
    size_t snapshot_tx_interval = max_tx_interval;

    struct SnapshotInfo
    {
      kv::Version version;
      crypto::Sha256Hash write_set_digest;
      std::string commit_evidence;
      crypto::Sha256Hash snapshot_digest;
      std::vector<uint8_t> serialised_snapshot;

      // Prevents the receipt from being passed to the host (on commit) in case
      // host has not yet allocated memory for the snapshot.
      bool is_stored = false;

      std::optional<consensus::Index> evidence_idx = std::nullopt;

      std::optional<NodeId> node_id = std::nullopt;
      std::optional<crypto::Pem> node_cert = std::nullopt;
      std::optional<std::vector<uint8_t>> sig = std::nullopt;
      std::optional<std::vector<uint8_t>> tree = std::nullopt;

      SnapshotInfo() = default;
    };
    // Queue of pending snapshots that have been generated, but are not yet
    // committed
    std::map<uint32_t, SnapshotInfo> pending_snapshots;

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
      uint32_t generation_count;
    };

    static void snapshot_cb(std::unique_ptr<threading::Tmsg<SnapshotMsg>> msg)
    {
      msg->data.self->snapshot_(
        std::move(msg->data.snapshot), msg->data.generation_count);
    }

    void snapshot_(
      std::unique_ptr<kv::AbstractStore::AbstractSnapshot> snapshot,
      uint32_t generation_count)
    {
      if (pending_snapshots.size() >= max_pending_snapshots_count)
      {
        LOG_FAIL_FMT(
          "Skipping new snapshot generation as {} snapshots are already "
          "pending",
          pending_snapshots.size());
        return;
      }

      auto snapshot_version = snapshot->get_version();

      auto serialised_snapshot = store->serialise_snapshot(std::move(snapshot));
      auto serialised_snapshot_size = serialised_snapshot.size();

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
      pending_snapshots[generation_count] = {};
      pending_snapshots[generation_count].version = snapshot_version;

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

      auto evidence_version = tx.commit_version();

      pending_snapshots[generation_count].commit_evidence = commit_evidence;
      pending_snapshots[generation_count].write_set_digest = ws_digest;
      pending_snapshots[generation_count].snapshot_digest = cd.value();
      pending_snapshots[generation_count].serialised_snapshot =
        std::move(serialised_snapshot);

      auto to_host = writer_factory.create_writer_to_outside();
      RINGBUFFER_WRITE_MESSAGE(
        consensus::snapshot_allocate,
        to_host,
        snapshot_version,
        evidence_version,
        serialised_snapshot_size,
        generation_count);

      LOG_DEBUG_FMT(
        "Request to allocate snapshot [{} bytes] for seqno {}, with evidence "
        "seqno {}: {}, ws digest: {}",
        serialised_snapshot_size,
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
        auto& snapshot_info = it->second;

        if (
          snapshot_info.is_stored && snapshot_info.evidence_idx.has_value() &&
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

          commit_snapshot(snapshot_info.version, serialised_receipt);
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

    bool write_snapshot(
      std::span<uint8_t> snapshot_buf, uint32_t generation_count)
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);

      auto search = pending_snapshots.find(generation_count);
      if (search == pending_snapshots.end())
      {
        LOG_FAIL_FMT(
          "Could not find pending snapshot to write for generation count {}",
          generation_count);
        return false;
      }

      auto& pending_snapshot = search->second;
      if (snapshot_buf.size() != pending_snapshot.serialised_snapshot.size())
      {
        // Unreliable host: allocated snapshot buffer is not of expected
        // size. The pending snapshot is discarded to reduce enclave memory
        // usage.
        LOG_FAIL_FMT(
          "Host allocated snapshot buffer [{} bytes] is not of expected "
          "size [{} bytes]. Discarding snapshot for seqno {}",
          snapshot_buf.size(),
          pending_snapshot.serialised_snapshot.size(),
          pending_snapshot.version);
        pending_snapshots.erase(search);
        return false;
      }
      else if (!ccf::pal::is_outside_enclave(
                 snapshot_buf.data(), snapshot_buf.size()))
      {
        // Sanitise host-allocated buffer. Note that buffer alignment is not
        // checked as the buffer is only written to and never read.
        LOG_FAIL_FMT(
          "Host allocated snapshot buffer is not outside enclave memory. "
          "Discarding snapshot for seqno {}",
          pending_snapshot.version);
        pending_snapshots.erase(search);
        return false;
      }

      ccf::pal::speculation_barrier();

      std::copy(
        pending_snapshot.serialised_snapshot.begin(),
        pending_snapshot.serialised_snapshot.end(),
        snapshot_buf.begin());
      pending_snapshot.is_stored = true;

      LOG_DEBUG_FMT(
        "Successfully copied snapshot at seqno {} to host memory [{} "
        "bytes]",
        pending_snapshot.version,
        pending_snapshot.serialised_snapshot.size());
      return true;
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

      for (auto& [_, pending_snapshot] : pending_snapshots)
      {
        if (
          pending_snapshot.evidence_idx.has_value() &&
          idx > pending_snapshot.evidence_idx.value() &&
          !pending_snapshot.sig.has_value())
        {
          LOG_TRACE_FMT(
            "Recording signature at {} for snapshot {} with evidence at {}",
            idx,
            pending_snapshot.version,
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

      for (auto& [_, pending_snapshot] : pending_snapshots)
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
            pending_snapshot.version,
            pending_snapshot.evidence_idx.value());

          pending_snapshot.tree = tree;
        }
      }
    }

    void record_snapshot_evidence_idx(
      consensus::Index idx, const SnapshotHash& snapshot)
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);

      for (auto& [_, pending_snapshot] : pending_snapshots)
      {
        if (pending_snapshot.version == snapshot.version)
        {
          LOG_TRACE_FMT(
            "Recording evidence idx at {} for snapshot {}",
            idx,
            pending_snapshot.version);

          pending_snapshot.evidence_idx = idx;
        }
      }
    }

    void schedule_snapshot(consensus::Index idx)
    {
      static uint32_t generation_count = 0;
      auto msg = std::make_unique<threading::Tmsg<SnapshotMsg>>(&snapshot_cb);
      msg->data.self = shared_from_this();
      msg->data.snapshot = store->snapshot_unsafe_maps(idx);
      msg->data.generation_count = generation_count++;

      auto& tm = threading::ThreadMessaging::instance();
      tm.add_task(tm.get_execution_thread(generation_count), std::move(msg));
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
