// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/indexing/strategy.h"
#include "indexing/indexing_types.h"

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
      const kv::serialisers::SerialisedEntry& k,
      const kv::serialisers::SerialisedEntry& v) = 0;

  public:
    VisitEachEntryInMap(
      const std::string& map_name_,
      const std::string& strategy_prefix = "VisitEachEntryIn") :
      Strategy(fmt::format("{} {}", strategy_prefix, map_name_)),
      map_name(map_name_)
    {}

    void handle_committed_transaction(
      const ccf::TxID& tx_id, const StorePtr& store) override
    {
      // NB: Get an untyped view over the map with the same name. This saves
      // deserialisation here, where we hand on the raw key and value.
      auto tx = store->create_read_only_tx();
      auto handle = tx.ro<kv::untyped::Map>(map_name);

      handle->foreach([this, &tx_id](const auto& k, const auto& v) {
        visit_entry(tx_id, k, v);
        return true;
      });
      current_txid = tx_id;
    }

    std::optional<ccf::SeqNo> next_requested() override
    {
      return current_txid.seqno + 1;
    }

    ccf::TxID get_indexed_watermark() const
    {
      return current_txid;
    }
  };
}
