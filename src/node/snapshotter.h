// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "crypto/hash.h"
#include "ds/ccf_assert.h"
#include "ds/logger.h"
#include "ds/thread_messaging.h"
#include "kv/kv_types.h"
#include "node/snapshot_evidence.h"

#include <optional>

namespace ccf
{
  class Snapshotter : public std::enable_shared_from_this<Snapshotter>
  {
  private:
    ringbuffer::WriterPtr to_host;

    NetworkState& network;

    size_t snapshot_interval;

    // Index at which the lastest snapshot was generated
    consensus::Index last_snapshot_idx = 0;

    // Index at which a snapshot will be next generated
    consensus::Index next_snapshot_idx = 0;

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
        consensus::ledger_snapshot, to_host, idx, serialised_snapshot);
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
      auto snapshot_idx = snapshot->get_version();

      auto serialised_snapshot =
        network.tables->serialise_snapshot(std::move(snapshot));

      kv::Tx tx;
      auto view = tx.get_view(network.snapshot_evidence);
      auto snapshot_hash = crypto::Sha256Hash(serialised_snapshot);
      view->put(0, {snapshot_hash, snapshot_idx});

      auto rc = tx.commit();
      if (rc != kv::CommitSuccess::OK)
      {
        LOG_FAIL_FMT(
          "Could not commit snapshot evidence for idx {}: {}",
          snapshot_idx,
          rc);
        return;
      }

      record_snapshot(snapshot_idx, serialised_snapshot);

      LOG_DEBUG_FMT(
        "Snapshot successfully generated for idx {}: {}",
        snapshot_idx,
        snapshot_hash);
    }

  public:
    Snapshotter(
      ringbuffer::AbstractWriterFactory& writer_factory,
      NetworkState& network_,
      size_t snapshot_interval_) :
      to_host(writer_factory.create_writer_to_outside()),
      network(network_),
      snapshot_interval(snapshot_interval_)
    {}

    void snapshot(consensus::Index idx)
    {
      CCF_ASSERT_FMT(
        idx >= last_snapshot_idx,
        "Cannot snapshot at idx {} which is earlier than last snapshot idx "
        "{}",
        idx,
        last_snapshot_idx);

      if (idx - last_snapshot_idx > snapshot_interval)
      {
        auto msg = std::make_unique<threading::Tmsg<SnapshotMsg>>(&snapshot_cb);
        msg->data.self = shared_from_this();
        msg->data.snapshot = network.tables->snapshot(idx);

        last_snapshot_idx = idx;
        threading::ThreadMessaging::thread_messaging.add_task(
          get_execution_thread(), std::move(msg));
      }
    }

    // TODO: Name is baaaad
    bool requires_snapshot(consensus::Index idx)
    {
      if ((idx - next_snapshot_idx) > snapshot_interval)
      {
        next_snapshot_idx = idx;
        return true;
      }
      return false;
    }
  };
}