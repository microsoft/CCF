// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/indexing/strategies/visit_each_entry_in_map.h"

#include "kv/store.h"

namespace ccf::indexing::strategies
{
  VisitEachEntryInMap::VisitEachEntryInMap(
    const std::string& map_name_, const std::string& strategy_prefix) :
    Strategy(fmt::format("{} {}", strategy_prefix, map_name_)),
    map_name(map_name_)
  {}

  void VisitEachEntryInMap::handle_committed_transaction(
    const ccf::TxID& tx_id, const kv::ReadOnlyStorePtr& store)
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

  std::optional<ccf::SeqNo> VisitEachEntryInMap::next_requested()
  {
    return current_txid.seqno + 1;
  }

  nlohmann::json VisitEachEntryInMap::describe()
  {
    auto j = Strategy::describe();
    j["target_map"] = map_name;
    j["indexed_watermark"] = get_indexed_watermark();
    return j;
  }

  ccf::TxID VisitEachEntryInMap::get_indexed_watermark() const
  {
    return current_txid;
  }
}
