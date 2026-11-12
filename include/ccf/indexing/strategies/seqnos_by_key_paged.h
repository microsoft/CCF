// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/byte_vector.h"
#include "ccf/indexing/strategy.h"
#include "ccf/node_context.h"
#include "ccf/seq_no_collection.h"

namespace ccf::indexing::strategies
{
  /** Node-local, public-table B+ tree. See architecture/indexing for limits
   * and the single-active-query retry contract.
   */
  class SeqnosByKey_Paged_Untyped : public Strategy
  {
    struct Impl;
    std::unique_ptr<Impl> impl;

  protected:
    std::optional<SeqNoCollection> get_write_txs_impl(
      const ccf::ByteVector& key, ccf::SeqNo from, ccf::SeqNo to);

  public:
    SeqnosByKey_Paged_Untyped(
      const std::string& map_name,
      ccf::AbstractNodeContext& context,
      size_t page_bytes = 4096,
      size_t cache_bytes = 65536);
    ~SeqnosByKey_Paged_Untyped() override;

    void handle_committed_transaction(
      const ccf::TxID& tx_id, const ccf::kv::ReadOnlyStorePtr& store) override;
    void tick() override;
    std::optional<ccf::SeqNo> next_requested() override;
    ccf::TxID get_indexed_watermark();
    void cancel_query();
    // Request an asynchronous checkpoint of the bounded trusted working set.
    void flush();
    nlohmann::json describe() override;
  };

  template <typename M>
  class SeqnosByKey_Paged : public SeqnosByKey_Paged_Untyped
  {
  public:
    using SeqnosByKey_Paged_Untyped::SeqnosByKey_Paged_Untyped;

    SeqnosByKey_Paged(
      const M& map,
      ccf::AbstractNodeContext& context,
      size_t page_bytes = 4096,
      size_t cache_bytes = 65536) :
      SeqnosByKey_Paged_Untyped(
        map.get_name(), context, page_bytes, cache_bytes)
    {}

    std::optional<SeqNoCollection> get_write_txs_in_range(
      const typename M::Key& key, ccf::SeqNo from, ccf::SeqNo to)
    {
      return get_write_txs_impl(M::KeySerialiser::to_serialised(key), from, to);
    }
  };
}
