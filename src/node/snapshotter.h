// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "crypto/hash.h"
#include "ds/ccf_assert.h"
#include "ds/logger.h"
#include "ds/spin_lock.h"
#include "ds/thread_messaging.h"
#include "kv/kv_types.h"
#include "kv/tx.h"
#include "node/network_state.h"
#include "node/snapshot_evidence.h"

#include <deque>

namespace ccf
{
  class Snapshotter : public std::enable_shared_from_this<Snapshotter>
  {
  public:
    static constexpr auto max_tx_interval = std::numeric_limits<size_t>::max();

  private:
    ringbuffer::WriterPtr to_host;
    SpinLock lock;

    NetworkState& network;

    // Snapshots are never generated by default (e.g. during public recovery)
    size_t snapshot_tx_interval = max_tx_interval;

    struct SnapshotInfo
    {
      consensus::Index idx;
      consensus::Index evidence_idx;
    };
    std::deque<SnapshotInfo> snapshot_evidence_indices;

    // Index at which the lastest snapshot was generated
    consensus::Index last_snapshot_idx = 0;

    // Indices at which a snapshot will be next generated
    std::deque<consensus::Index> next_snapshot_indices;

    size_t get_execution_thread()
    {
      // Generate on main thread if there are no worker threads. Otherwise,
      // round robin on worker threads.
      if (threading::ThreadMessaging::thread_count > 1)
      {
        static size_t generation_count = 0;
        return (generation_count++ % threading::ThreadMessaging::thread_count) +
          1;
      }
      else
      {
        return threading::MAIN_THREAD_ID;
      }
    }

    void record_snapshot(
      consensus::Index idx, const std::vector<uint8_t>& serialised_snapshot)
    {
      RINGBUFFER_WRITE_MESSAGE(
        consensus::snapshot, to_host, idx, serialised_snapshot);
    }

    void commit_snapshot(
      consensus::Index snapshot_idx, consensus::Index evidence_idx)
    {
      // The snapshot_idx is used to retrieve the correct snapshot file
      // previously generated. The evidence_idx is recorded as metadata.
      RINGBUFFER_WRITE_MESSAGE(
        consensus::snapshot_commit, to_host, snapshot_idx, evidence_idx);
    }

    struct SnapshotMsg
    {
      std::shared_ptr<Snapshotter> self;
      std::unique_ptr<kv::AbstractStore::AbstractSnapshot> snapshot;
    };

    static void snapshot_cb(std::unique_ptr<threading::Tmsg<SnapshotMsg>> msg)
    {
      msg->data.self->snapshot_(std::move(msg->data.snapshot));
    }

    void snapshot_(
      std::unique_ptr<kv::AbstractStore::AbstractSnapshot> snapshot)
    {
      auto snapshot_v = snapshot->get_version();

      auto serialised_snapshot =
        network.tables->serialise_snapshot(std::move(snapshot));

      auto tx = network.tables->create_tx();
      auto view = tx.get_view(network.snapshot_evidence);
      auto snapshot_hash = crypto::Sha256Hash(serialised_snapshot);
      view->put(0, {snapshot_hash, snapshot_v});

      auto rc = tx.commit();
      if (rc != kv::CommitSuccess::OK)
      {
        LOG_FAIL_FMT(
          "Could not commit snapshot evidence for seqno {}: {}",
          snapshot_v,
          rc);
        return;
      }

      record_snapshot(snapshot_v, serialised_snapshot);
      consensus::Index snapshot_idx = static_cast<consensus::Index>(snapshot_v);
      consensus::Index snapshot_evidence_idx =
        static_cast<consensus::Index>(tx.commit_version());
      snapshot_evidence_indices.push_back(
        {snapshot_idx, snapshot_evidence_idx});

      LOG_DEBUG_FMT(
        "Snapshot successfully generated for seqno {}, with evidence seqno {}: "
        "{}",
        snapshot_idx,
        snapshot_evidence_idx,
        snapshot_hash);
    }

  public:
    Snapshotter(
      ringbuffer::AbstractWriterFactory& writer_factory,
      NetworkState& network_) :
      to_host(writer_factory.create_writer_to_outside()),
      network(network_)
    {
      next_snapshot_indices.push_back(last_snapshot_idx);
    }

    void set_tx_interval(size_t snapshot_tx_interval_)
    {
      std::lock_guard<SpinLock> guard(lock);
      snapshot_tx_interval = snapshot_tx_interval_;
    }

    void set_last_snapshot_idx(consensus::Index idx)
    {
      std::lock_guard<SpinLock> guard(lock);

      // Should only be called once, after a snapshot has been applied
      if (last_snapshot_idx != 0)
      {
        throw std::logic_error(
          "Last snapshot index can only be set if no snapshot has been "
          "generated");
      }

      last_snapshot_idx = idx;

      next_snapshot_indices.clear();
      next_snapshot_indices.push_back(last_snapshot_idx);
    }

    void snapshot(consensus::Index idx)
    {
      std::lock_guard<SpinLock> guard(lock);

      if (idx < last_snapshot_idx)
      {
        throw std::logic_error(fmt::format(
          "Cannot snapshot at seqno {} which is earlier than last snapshot "
          "seqno {}",
          idx,
          last_snapshot_idx));
      }

      if (idx - last_snapshot_idx >= snapshot_tx_interval)
      {
        auto msg = std::make_unique<threading::Tmsg<SnapshotMsg>>(&snapshot_cb);
        msg->data.self = shared_from_this();
        msg->data.snapshot = network.tables->snapshot(idx);

        last_snapshot_idx = idx;
        threading::ThreadMessaging::thread_messaging.add_task(
          get_execution_thread(), std::move(msg));
      }
    }

    void compact(consensus::Index idx)
    {
      std::lock_guard<SpinLock> guard(lock);

      while (!next_snapshot_indices.empty() &&
             (next_snapshot_indices.front() < idx))
      {
        next_snapshot_indices.pop_front();
      }

      if (next_snapshot_indices.empty())
      {
        next_snapshot_indices.push_back(last_snapshot_idx);
      }

      while (!snapshot_evidence_indices.empty() &&
             (snapshot_evidence_indices.front().evidence_idx <= idx))
      {
        auto snapshot_info = snapshot_evidence_indices.front();
        commit_snapshot(snapshot_info.idx, snapshot_info.evidence_idx);
        snapshot_evidence_indices.pop_front();
      }
    }

    bool requires_snapshot(consensus::Index idx)
    {
      std::lock_guard<SpinLock> guard(lock);

      // Returns true if the idx will require the generation of a snapshot
      if ((idx - next_snapshot_indices.back()) >= snapshot_tx_interval)
      {
        next_snapshot_indices.push_back(idx);
        return true;
      }
      return false;
    }

    void rollback(consensus::Index idx)
    {
      std::lock_guard<SpinLock> guard(lock);

      while (!next_snapshot_indices.empty() &&
             (next_snapshot_indices.back() > idx))
      {
        next_snapshot_indices.pop_back();
      }

      if (next_snapshot_indices.empty())
      {
        next_snapshot_indices.push_back(last_snapshot_idx);
      }

      while (!snapshot_evidence_indices.empty() &&
             (snapshot_evidence_indices.back().evidence_idx > idx))
      {
        snapshot_evidence_indices.pop_back();
      }
    }
  };
}