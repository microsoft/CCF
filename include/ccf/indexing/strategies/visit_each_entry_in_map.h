// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/byte_vector.h"
#include "ccf/indexing/strategy.h"

namespace ccf::indexing::strategies
{
  // A meta-strategy which takes a target map, requests every Tx in-order, and
  // visits each written KV pair in the target map in each Tx. Derived classes
  // override visit_entry() to construct/store their index.
  class VisitEachEntryInMap : public Strategy
  {
  protected:
    std::string map_name;
    ccf::TxID current_txid = {};

    virtual void visit_entry(
      const ccf::TxID& tx_id,
      const ccf::ByteVector& k,
      const ccf::ByteVector& v) = 0;

  public:
    VisitEachEntryInMap(
      const std::string& map_name_,
      const std::string& strategy_prefix = "VisitEachEntryIn");

    virtual ~VisitEachEntryInMap() = default;

    void handle_committed_transaction(
      const ccf::TxID& tx_id, const kv::ReadOnlyStorePtr& store) override;
    std::optional<ccf::SeqNo> next_requested() override;

    nlohmann::json describe() override;

    ccf::TxID get_indexed_watermark() const;
  };
}
