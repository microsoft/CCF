// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"
#include "ds/logger.h"

#include <kv/kv_types.h>

namespace ccf
{
  class Snapshotter
  {
  private:
    ringbuffer::WriterPtr to_host;
    std::shared_ptr<kv::AbstractStore> store;

    consensus::Index last_snapshot_idx = 0;
    size_t snapshot_interval;

    void record_snapshot(
      consensus::Index idx, const std::vector<uint8_t>& serialised_snapshot)
    {
      RINGBUFFER_WRITE_MESSAGE(
        consensus::ledger_snapshot, to_host, idx, serialised_snapshot);
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

    std::optional<consensus::Index> snapshot(consensus::Index idx)
    {
      if (idx < last_snapshot_idx)
      {
        LOG_FAIL_FMT(
          "Cannot snapshot at idx {} which is earlier than last snapshot idx "
          "{}",
          idx,
          last_snapshot_idx);
        return std::nullopt;
      }

      if (idx - last_snapshot_idx > snapshot_interval)
      {
        auto snapshot = store->serialise_snapshot(idx);
        record_snapshot(idx, snapshot);

        last_snapshot_idx = idx;
        return idx;
      }

      return std::nullopt;
    }
  };
}