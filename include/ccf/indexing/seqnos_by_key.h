// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/indexing/strategy.h"
#include "indexing/indexing_types.h"

#include <memory>
#include <string>

namespace ccf::indexing::strategies
{
  template <typename M>
  class SeqnosByKey : public Strategy
  {
  private:
    // Key is the raw value of a KV key.
    // Value is every SeqNo which talks about that key.
    // This entire structure should be shardable, so we can dump parts of it to
    // disk!
    std::unordered_map<kv::untyped::SerialisedEntry, SeqNoCollection>
      seqnos_by_key;

    ccf::TxID current_txid = {};

    std::string map_name;

  public:
    SeqnosByKey(const std::string& map_name_) :
      Strategy(fmt::format("SeqnosByKey for {}", map_name_)),
      map_name(map_name_)
    {}

    SeqnosByKey(const M& map) : SeqnosByKey(map.get_name()) {}

    void handle_committed_transaction(
      const ccf::TxID& tx_id, const StorePtr& store) override
    {
      // NB: Don't use M, instead get an untyped view over the map with the same
      // name. This saves deserialisation here, where we work with the raw key.
      auto tx = store->create_read_only_tx();
      auto handle = tx.ro<kv::untyped::Map>(map_name);
      handle->foreach(
        [this, seqno = tx_id.seqno](const auto& k, const auto& v) {
          seqnos_by_key[k].insert(seqno);
          return true;
        });
      current_txid = tx_id;
    }

    ccf::TxID get_indexed_watermark() const
    {
      return current_txid;
    }

    SeqNoCollection get_all_write_txs(const typename M::Key& key)
    {
      const auto serialised_key = M::KeySerialiser::to_serialised(key);
      const auto it = seqnos_by_key.find(serialised_key);
      if (it != seqnos_by_key.end())
      {
        return it->second;
      }

      return SeqNoCollection();
    }

    std::optional<SeqNoCollection> get_write_txs_in_range(
      const typename M::Key& key,
      ccf::SeqNo from,
      ccf::SeqNo to,
      std::optional<size_t> max_seqnos = std::nullopt)
    {
      if (to > current_txid.seqno)
      {
        // If the requested range hasn't been populated yet, indicate
        // that with nullopt
        return std::nullopt;
      }

      const auto serialised_key = M::KeySerialiser::to_serialised(key);
      const auto it = seqnos_by_key.find(serialised_key);
      if (it != seqnos_by_key.end())
      {
        SeqNoCollection& seqnos = it->second;
        auto from_it = seqnos.lower_bound(from);
        auto to_it = from_it;

        if (
          max_seqnos.has_value() &&
          (size_t)(seqnos.end() - from_it) > *max_seqnos)
        {
          to_it += *max_seqnos;
        }
        else
        {
          to_it = seqnos.upper_bound(to);
        }

        SeqNoCollection sub_range(from_it, to_it);
        return sub_range;
      }

      // In this case we have seen every tx in the requested range, but have not
      // seen the target key at all
      return SeqNoCollection();
    }
  };
}