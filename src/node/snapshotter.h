// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "crypto/hash.h"
#include "ds/ccf_assert.h"
#include "ds/logger.h"
#include "ds/spin_lock.h"
#include "ds/thread_messaging.h"
#include "node/snapshot_evidence.h"

#include <kv/kv_types.h>

namespace ccf
{
  class Snapshotter : public std::enable_shared_from_this<Snapshotter>
  {
  private:
    ringbuffer::WriterPtr to_host;
    SpinLock lock;

    NetworkState& network;

    consensus::Index last_snapshot_idx = 0;
    size_t snapshot_interval;

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
      consensus::Index idx;
    };

    static void snapshot_cb(std::unique_ptr<threading::Tmsg<SnapshotMsg>> msg)
    {
      msg->data.self->snapshot_(msg->data.idx);
    }

    void snapshot_(consensus::Index idx)
    {
      std::lock_guard<SpinLock> guard(lock);

      auto snapshot = network.tables->serialise_snapshot(idx);

      kv::Tx tx;
      auto view = tx.get_view(network.snapshot_evidences);
      auto snapshot_hash = crypto::Sha256Hash(snapshot);
      view->put(0, {snapshot_hash, idx});

      auto rc = tx.commit();
      if (rc != kv::CommitSuccess::OK)
      {
        LOG_FAIL_FMT(
          "Could not commit snapshot evidence for idx {}: {}", idx, rc);
        return;
      }

      record_snapshot(idx, snapshot);
      last_snapshot_idx = idx;

      LOG_DEBUG_FMT(
        "Snapshot successfully generated for idx {}: {}", idx, snapshot_hash);
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
      std::lock_guard<SpinLock> guard(lock);

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
        msg->data.idx = idx;

        threading::ThreadMessaging::thread_messaging.add_task(
          get_execution_thread(), std::move(msg));
      }
    }
  };
}