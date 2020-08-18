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
    std::optional<std::vector<uint8_t>> hash_at_snapshot = std::nullopt;

  public:
    StoreSnapshot() = default;

    void add_map_snapshot(
      std::unique_ptr<kv::AbstractMap::Snapshot> snapshot) override
    {
      snapshots.push_back(std::move(snapshot));
    }

    void add_hash_at_snapshot(std::vector<uint8_t>&& hash_at_snapshot_)
    {
      hash_at_snapshot = std::move(hash_at_snapshot_);
    }

    std::vector<uint8_t> serialise(KvStoreSerialiser& s) override
    {
      if (hash_at_snapshot.has_value())
      {
        s.serialise_raw(hash_at_snapshot.value());
      }

      for (auto domain : {SecurityDomain::PUBLIC, SecurityDomain::PRIVATE})
      {
        for (const auto& it : snapshots)
        {
          if (it->get_security_domain() == domain)
          {
            it->serialise(s);
          }
        }
      }

      return s.get_raw_data();
    }
  };
}