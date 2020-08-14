// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "ds/logger.h"

#include <kv/kv_types.h>

namespace ccf
{
  // TODO: Delete
  // class AbstractSnapshotter
  // {
  // public:
  //   virtual ~AbstractSnapshotter() = default;

  //   void snapshot(kv::Version version) = 0;
  // };

  // TODO: Probably need a lock on this????

  class Snapshotter
  {
  private:
    ringbuffer::WriterPtr to_host;
    std::shared_ptr<kv::AbstractStore> store;

    size_t last_snapshot_idx = 0;
    size_t snapshot_interval;

    void record_snapshot(
      kv::Version version, const std::vector<uint8_t>& serialised_snapshot)
    {
      RINGBUFFER_WRITE_MESSAGE(
        consensus::ledger_snapshot, to_host, version, serialised_snapshot);
    }

  public:
    Snapshotter(
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::shared_ptr<kv::AbstractStore> store_,
      size_t snapshot_interval_) :
      to_host(writer_factory.create_writer_to_outside()),
      store(store_),
      snapshot_interval(snapshot_interval_)
    {}

    void snapshot(kv::Version version)
    {
      if ((unsigned)(version - last_snapshot_idx) > snapshot_interval)
      {
        LOG_FAIL_FMT("Creating snapshot at {} [NO EFFECT]", version);
        auto snapshot = store->serialise_snapshot(version);
        record_snapshot(version, snapshot);

        last_snapshot_idx = version;
      }
      LOG_FAIL_FMT("Not snapshotting...");
    }
  };
}