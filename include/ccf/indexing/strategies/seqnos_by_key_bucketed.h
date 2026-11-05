// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/indexing/strategies/visit_each_entry_in_map.h"
#include "ccf/node_context.h"
#include "ccf/seq_no_collection.h"

namespace ccf::indexing::strategies
{
  // Retains a trusted current bucket for every distinct key. Completed
  // non-empty buckets and immutable directory pages are authenticated by LFS
  // and fetched through bounded caches. Each key also retains an unfinished
  // directory page; memory still grows with the number of distinct keys.
  class SeqnosByKey_Bucketed_Untyped : public VisitEachEntryInMap
  {
  protected:
    struct Impl;
    std::shared_ptr<Impl> impl = nullptr;

    void visit_entry(
      const ccf::TxID& tx_id,
      const ccf::ByteVector& k,
      const ccf::ByteVector& v) override;

    nlohmann::json describe() override;

    std::optional<SeqNoCollection> get_write_txs_impl(
      const ccf::ByteVector& serialised_key, ccf::SeqNo from, ccf::SeqNo to);

  public:
    SeqnosByKey_Bucketed_Untyped(
      const std::string& map_name_,
      ccf::AbstractNodeContext& node_context,
      size_t seqnos_per_bucket_ = 1000,
      size_t max_buckets_ = 10);

    // Inclusive queries with to - from above this limit are rejected.
    // Directory lookup progresses across asynchronous retries independently
    // of file-cache eviction.
    [[nodiscard]] size_t max_requestable_range() const;
  };

  template <typename M>
  class SeqnosByKey_Bucketed : public SeqnosByKey_Bucketed_Untyped
  {
  public:
    using SeqnosByKey_Bucketed_Untyped::SeqnosByKey_Bucketed_Untyped;

    SeqnosByKey_Bucketed(
      const M& map,
      ccf::AbstractNodeContext& node_context,
      size_t seqnos_per_bucket_ = 1000,
      size_t max_buckets_ = 10) :
      SeqnosByKey_Bucketed_Untyped(
        map.get_name(), node_context, seqnos_per_bucket_, max_buckets_)
    {}

    std::optional<SeqNoCollection> get_write_txs_in_range(
      const typename M::Key& key, ccf::SeqNo from, ccf::SeqNo to)
    {
      return get_write_txs_impl(M::KeySerialiser::to_serialised(key), from, to);
    }
  };

  template <typename V>
  class SeqnosForValue_Bucketed : public SeqnosByKey_Bucketed_Untyped
  {
  public:
    using SeqnosByKey_Bucketed_Untyped::SeqnosByKey_Bucketed_Untyped;

    SeqnosForValue_Bucketed(
      const V& value,
      ccf::AbstractNodeContext& node_context,
      size_t seqnos_per_bucket_ = 1000,
      size_t max_buckets_ = 10) :
      SeqnosByKey_Bucketed_Untyped(
        value.get_name(), node_context, seqnos_per_bucket_, max_buckets_)
    {}

    std::optional<SeqNoCollection> get_write_txs_in_range(
      ccf::SeqNo from, ccf::SeqNo to)
    {
      static const auto singleton = V::create_unit();
      return get_write_txs_impl(singleton, from, to);
    }
  };
}
