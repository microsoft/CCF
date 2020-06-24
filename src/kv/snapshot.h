// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"

namespace kv
{
  class StoreSnapshot : public AbstractStore::AbstractSnapshot
  {
  private:
    std::vector<std::unique_ptr<kv::AbstractMap::Snapshot>> snapshots;
    kv::Version version;
    size_t serialized_size = 0;
    std::vector<uint8_t> buffer;

  public:
    StoreSnapshot(kv::Version version_) : version(version_) {}

    void add_snapshot(std::unique_ptr<kv::AbstractMap::Snapshot> snapshot)
    {
      serialized_size += snapshot->get_serialized_size();
      snapshots.push_back(std::move(snapshot));
    }

    std::vector<std::unique_ptr<kv::AbstractMap::Snapshot>>& get_snapshots()
    {
      return snapshots;
    }

    std::vector<uint8_t>& get_buffer()
    {
      buffer.resize(serialized_size);
      return buffer;
    }

    void serialize()
    {
      uint8_t* buffer = get_buffer().data();
      uint32_t position = 0;
      for (auto& s : snapshots)
      {
        s->serialize(buffer);
        buffer = buffer + s->get_serialized_size();
      }
    }

    kv::Version get_version() const
    {
      return version;
    }
  };
}