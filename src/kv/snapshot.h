// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"

namespace kv
{
  class StoreSnapshot : public AbstractStore::AbstractSnapshot
  {
  private:
    Version version;

    std::vector<std::unique_ptr<kv::AbstractMap::Snapshot>> snapshots;
    std::optional<std::vector<uint8_t>> hash_at_snapshot = std::nullopt;

  public:
    StoreSnapshot(Version version_) : version(version_) {}

    void add_map_snapshot(std::unique_ptr<kv::AbstractMap::Snapshot> snapshot)
    {
      snapshots.push_back(std::move(snapshot));
    }

    void add_hash_at_snapshot(std::vector<uint8_t>&& hash_at_snapshot_)
    {
      hash_at_snapshot = std::move(hash_at_snapshot_);
    }

    Version get_version() const
    {
      return version;
    }

    std::vector<uint8_t> serialise(
      std::shared_ptr<AbstractTxEncryptor> encryptor)
    {
      KvStoreSerialiser serialiser(encryptor, version, true);

      if (hash_at_snapshot.has_value())
      {
        serialiser.serialise_raw(hash_at_snapshot.value());
      }

      for (auto domain : {SecurityDomain::PUBLIC, SecurityDomain::PRIVATE})
      {
        for (const auto& it : snapshots)
        {
          if (it->get_security_domain() == domain)
          {
            it->serialise(serialiser);
          }
        }
      }

      return serialiser.get_raw_data();
    }
  };
}