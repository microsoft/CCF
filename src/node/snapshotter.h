// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "ds/ccf_assert.h"
#include "ds/spin_lock.h"
#include "ds/thread_messaging.h"

#include <kv/kv_types.h>

namespace ccf
{
  class Snapshotter : public std::enable_shared_from_this<Snapshotter>
  {
  private:
    ringbuffer::WriterPtr to_host;
    SpinLock lock;
    size_t execution_thread;

    std::shared_ptr<kv::AbstractStore> store;

    consensus::Index last_snapshot_idx = 0;
    size_t snapshot_interval;

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

      auto snapshot = store->serialise_snapshot(idx);
      record_snapshot(idx, snapshot);

      LOG_DEBUG_FMT("Snapshot successfully generated at idx {}", idx);

      last_snapshot_idx = idx;
    }

  public:
    Snapshotter(
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::shared_ptr<kv::AbstractStore> store_,
      size_t snapshot_interval_) :
      to_host(writer_factory.create_writer_to_outside()),
      store(store_),
      snapshot_interval(snapshot_interval_)
    {
      // For now, always generate snapshots on first worker thread if there are
      // more than one thread
      // Warning: With 1+ worker threads, this still executes on the main thread
      // as the worker threads are initialised after the Snapshotter is created
      execution_thread = (threading::ThreadMessaging::thread_count > 1) ? 1 : 0;
    }

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
          execution_thread, std::move(msg));
      }
    }
  };
}