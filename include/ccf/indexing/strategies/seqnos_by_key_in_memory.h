// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/pal.h"
#include "ccf/indexing/strategies/visit_each_entry_in_map.h"
#include "ccf/seq_no_collection.h"

namespace ccf::indexing::strategies
{
  // A simple Strategy which stores one large map in-memory
  class SeqnosByKey_InMemory_Untyped : public VisitEachEntryInMap
  {
  protected:
    // Key is the raw value of a KV key.
    // Value is every SeqNo which talks about that key.
    std::unordered_map<ccf::ByteVector, SeqNoCollection> seqnos_by_key;

    // Mutex guarding access to seqnos_by_key
    ccf::Pal::Mutex lock;

    void visit_entry(
      const ccf::TxID& tx_id,
      const ccf::ByteVector& k,
      const ccf::ByteVector& v) override;

    std::optional<SeqNoCollection> get_write_txs_impl(
      const ccf::ByteVector& serialised_key,
      ccf::SeqNo from,
      ccf::SeqNo to,
      std::optional<size_t> max_seqnos = std::nullopt);

  public:
    SeqnosByKey_InMemory_Untyped(const std::string& map_name_) :
      VisitEachEntryInMap(map_name_, "SeqnosByKey")
    {}
  };

  template <typename M>
  class SeqnosByKey_InMemory : public SeqnosByKey_InMemory_Untyped
  {
  public:
    SeqnosByKey_InMemory(const M& map) :
      SeqnosByKey_InMemory_Untyped(map.get_name())
    {}

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
