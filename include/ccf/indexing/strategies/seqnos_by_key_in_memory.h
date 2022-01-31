// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/indexing/strategies/visit_each_entry_in_map.h"

namespace ccf::indexing::strategies
{
  // A simple Strategy which stores one large map in-memory
  template <typename M>
  class SeqnosByKey_InMemory : public VisitEachEntryInMap
  {
  protected:
    // Key is the raw value of a KV key.
    // Value is every SeqNo which talks about that key.
    std::unordered_map<kv::untyped::SerialisedEntry, SeqNoCollection>
      seqnos_by_key;

    void visit_entry(
      const ccf::TxID& tx_id,
      const kv::serialisers::SerialisedEntry& k,
      const kv::serialisers::SerialisedEntry& v) override
    {
      seqnos_by_key[k].insert(tx_id.seqno);
    }

    std::optional<SeqNoCollection> get_write_txs_impl(
      const kv::serialisers::SerialisedEntry& serialised_key,
      ccf::SeqNo from,
      ccf::SeqNo to,
      std::optional<size_t> max_seqnos = std::nullopt)
    {
      const auto it = seqnos_by_key.find(serialised_key);
      if (it != seqnos_by_key.end())
      {
        SeqNoCollection& seqnos = it->second;
        auto from_it = seqnos.lower_bound(from);
        auto to_it = from_it;

        if (
          max_seqnos.has_value() &&
          std::distance(from_it, seqnos.end()) > *max_seqnos)
        {
          std::advance(to_it, *max_seqnos);
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

  public:
    SeqnosByKey_InMemory(const std::string& map_name_) :
      VisitEachEntryInMap(map_name_, "SeqnosByKey")
    {}

    SeqnosByKey_InMemory(const M& map) : SeqnosByKey_InMemory(map.get_name()) {}

    std::optional<SeqNoCollection> get_write_txs_in_range(
      const typename M::Key& key,
      ccf::SeqNo from,
      ccf::SeqNo to,
      std::optional<size_t> max_seqnos = std::nullopt)
    {
      if (to < from)
      {
        throw std::logic_error(
          fmt::format("Range goes backwards: {} -> {}", from, to));
      }

      if (to > current_txid.seqno)
      {
        // If the requested range hasn't been populated yet, indicate
        // that with nullopt
        return std::nullopt;
      }

      return get_write_txs_impl(
        M::KeySerialiser::to_serialised(key), from, to, max_seqnos);
    }

    std::optional<SeqNoCollection> get_all_write_txs(const typename M::Key& key)
    {
      return get_write_txs_in_range(key, 0, current_txid.seqno);
    }
  };
}
