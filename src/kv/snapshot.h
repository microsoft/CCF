// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"

namespace ccf::kv
{
  class StoreSnapshot : public AbstractStore::AbstractSnapshot
  {
  private:
    Version version;

    std::vector<std::unique_ptr<ccf::kv::AbstractMap::Snapshot>> snapshots;
    std::optional<std::vector<uint8_t>> hash_at_snapshot = std::nullopt;
    std::optional<std::vector<Version>> view_history = std::nullopt;

  public:
    StoreSnapshot(Version version_) : version(version_) {}

    void add_map_snapshot(
      std::unique_ptr<ccf::kv::AbstractMap::Snapshot> snapshot)
    {
      snapshots.push_back(std::move(snapshot));
    }

    void add_hash_at_snapshot(std::vector<uint8_t>&& hash_at_snapshot_)
    {
      hash_at_snapshot = std::move(hash_at_snapshot_);
    }

    void add_view_history(std::vector<Version>&& view_history_)
    {
      view_history = std::move(view_history_);
    }

    [[nodiscard]] Version get_version() const override
    {
      return version;
    }

    std::vector<uint8_t> serialise(
      const std::shared_ptr<AbstractTxEncryptor>& encryptor) override
    {
      // Set the execution dependency for the snapshot to be the version
      // previous to said snapshot to ensure that the correct snapshot is
      // serialized.
      // Notes:
      // - Snapshots are always taken at compacted state so version only is
      // unique enough to prevent IV reuse
      // - Because snapshot generation and ledger rekey can be interleaved,
      // consider historical ledger secrets when encrypting snapshot (see
      // https://github.com/microsoft/CCF/issues/3796).
      KvStoreSerialiser serialiser(
        encryptor,
        {0, version},
        ccf::kv::EntryType::Snapshot,
        0,
        {},
        ccf::no_claims(),
        true /* historical_hint */);

      if (hash_at_snapshot.has_value())
      {
        serialiser.serialise_raw(hash_at_snapshot.value());
      }

      if (view_history.has_value())
      {
        serialiser.serialise_view_history(view_history.value());
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