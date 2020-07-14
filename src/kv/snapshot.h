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

  public:
    StoreSnapshot() = default;

    void add_map_snapshot(
      std::unique_ptr<kv::AbstractMap::Snapshot> snapshot) override
    {
      snapshots.push_back(std::move(snapshot));
    }

    std::vector<uint8_t> serialise(KvStoreSerialiser& s) override
    {
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