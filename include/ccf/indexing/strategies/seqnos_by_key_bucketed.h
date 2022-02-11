// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/indexing/lfs_interface.h"
#include "ccf/indexing/strategies/visit_each_entry_in_map.h"
#include "ccf/seq_no_collection.h"

namespace ccf::indexing::strategies
{
  // Stores only a subset of results in-memory, on-demand, and dumps the
  // remainder to disk. The size of the per-key buckets which will be retained,
  // and the number of buckets which may be held in-memory, are configurable
  class SeqnosByKey_Bucketed_Untyped : public VisitEachEntryInMap
  {
  protected:
    struct Impl;
    std::shared_ptr<Impl> impl = nullptr;

    void visit_entry(
      const ccf::TxID& tx_id,
      const ccf::ByteVector& k,
      const ccf::ByteVector& v) override;

    std::optional<SeqNoCollection> get_write_txs_impl(
      const ccf::ByteVector& serialised_key, ccf::SeqNo from, ccf::SeqNo to);

  public:
    SeqnosByKey_Bucketed_Untyped(
      const std::string& map_name_,
      AbstractLFSAccess& lfs_access_,
      size_t seqnos_per_bucket_ = 1000,
      size_t max_buckets_ = 10);

    size_t max_requestable_range() const;
  };

  template <typename M>
  class SeqnosByKey_Bucketed : public SeqnosByKey_Bucketed_Untyped
  {
  public:
    using SeqnosByKey_Bucketed_Untyped::SeqnosByKey_Bucketed_Untyped;

    SeqnosByKey_Bucketed(
      const M& map,
      AbstractLFSAccess& lfs_access_,
      size_t seqnos_per_bucket_ = 1000,
      size_t max_buckets_ = 10) :
      SeqnosByKey_Bucketed_Untyped(
        map.get_name(), lfs_access_, seqnos_per_bucket_, max_buckets_)
    {}

    std::optional<SeqNoCollection> get_write_txs_in_range(
      const typename M::Key& key, ccf::SeqNo from, ccf::SeqNo to)
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

      return get_write_txs_impl(M::KeySerialiser::to_serialised(key), from, to);
    }
  };
}
