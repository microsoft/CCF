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

    void add_map_snapshot(
      std::unique_ptr<kv::AbstractMap::Snapshot> snapshot) override
    {
      serialized_size += snapshot->get_serialized_size();
      snapshots.push_back(std::move(snapshot));
    }

    const std::vector<std::unique_ptr<kv::AbstractMap::Snapshot>>&
    get_map_snapshots() override
    {
      return snapshots;
    }

    void serialize() override
    {
      buffer.resize(serialized_size);
      uint8_t* buffer_ = buffer.data();
      for (auto& s : snapshots)
      {
        s->serialize(buffer_);
        buffer_ = buffer_ + s->get_serialized_size();
      }
    }

    kv::Version get_version() const override
    {
      return version;
    }
  };
}