// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/indexing/strategies/seqnos_by_key_in_memory.h"

#include "ccf/pal/locking.h"

namespace ccf::indexing::strategies
{
  void SeqnosByKey_InMemory_Untyped::visit_entry(
    const ccf::TxID& tx_id, const ccf::ByteVector& k, const ccf::ByteVector& v)
  {
    (void) v;
    std::lock_guard<ccf::pal::Mutex> guard(lock);
    seqnos_by_key[k].insert(tx_id.seqno);
  }

  std::optional<SeqNoCollection> SeqnosByKey_InMemory_Untyped::
    get_write_txs_impl(
      const ccf::ByteVector& serialised_key,
      ccf::SeqNo from,
      ccf::SeqNo to,
      std::optional<size_t> max_seqnos)
  {
    std::lock_guard<ccf::pal::Mutex> guard(lock);
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
}
