// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/indexing/strategies/visit_each_entry_in_map.h"
#include "ccf/node_context.h"
#include "ccf/seq_no_collection.h"

namespace ccf::indexing::strategies
{
  struct SortedIndexOptions
  {
    // Flush threshold, checked between transactions; one transaction may exceed
    // it.
    size_t write_buffer_bytes = 64 * 1024;
    size_t block_bytes = 64 * 1024;
    // Block payload/decoding budget; LRU metadata and results are additional.
    size_t query_cache_bytes = 4 * 1024 * 1024;
    // Flush/merge work per tick; ingestion processes entire transactions.
    size_t entries_per_tick = 512;
  };

  class SeqnosByKey_Sorted_Untyped : public VisitEachEntryInMap
  {
  protected:
    struct Impl;
    std::unique_ptr<Impl> impl;
    void advance_maintenance();

    void visit_entry(
      const ccf::TxID& tx_id,
      const ccf::ByteVector& k,
      const ccf::ByteVector& v) override;
    std::optional<SeqNoCollection> get_write_txs_impl(
      const ccf::ByteVector& key, ccf::SeqNo from, ccf::SeqNo to);

  public:
    SeqnosByKey_Sorted_Untyped(
      const std::string& map_name,
      ccf::AbstractNodeContext& context,
      const SortedIndexOptions& options = {});
    ~SeqnosByKey_Sorted_Untyped() override;

    void handle_committed_transaction(
      const ccf::TxID& tx_id, const ccf::kv::ReadOnlyStorePtr& store) override;
    void tick() override;
    std::optional<ccf::SeqNo> next_requested() override;
    nlohmann::json describe() override;
  };

  template <typename M>
  class SeqnosByKey_Sorted : public SeqnosByKey_Sorted_Untyped
  {
  public:
    using SeqnosByKey_Sorted_Untyped::SeqnosByKey_Sorted_Untyped;

    SeqnosByKey_Sorted(
      const M& map,
      ccf::AbstractNodeContext& context,
      const SortedIndexOptions& options = {}) :
      SeqnosByKey_Sorted_Untyped(map.get_name(), context, options)
    {}

    // Throws std::length_error if the query's blocks cannot fit in the cache.
    std::optional<SeqNoCollection> get_write_txs_in_range(
      const typename M::Key& key, ccf::SeqNo from, ccf::SeqNo to)
    {
      return get_write_txs_impl(M::KeySerialiser::to_serialised(key), from, to);
    }
  };

  template <typename V>
  class SeqnosForValue_Sorted : public SeqnosByKey_Sorted_Untyped
  {
  public:
    using SeqnosByKey_Sorted_Untyped::SeqnosByKey_Sorted_Untyped;

    SeqnosForValue_Sorted(
      const V& value,
      ccf::AbstractNodeContext& context,
      const SortedIndexOptions& options = {}) :
      SeqnosByKey_Sorted_Untyped(value.get_name(), context, options)
    {}

    // Throws std::length_error if the query's blocks cannot fit in the cache.
    std::optional<SeqNoCollection> get_write_txs_in_range(
      ccf::SeqNo from, ccf::SeqNo to)
    {
      return get_write_txs_impl(V::create_unit(), from, to);
    }
  };
}
