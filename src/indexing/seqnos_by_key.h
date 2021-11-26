// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "indexing/indexing_types.h"
#include "indexing/strategy.h"

#include <memory>
#include <string>

namespace indexing::strategies
{
  class SeqnosByKey : public Strategy
  {
  private:
    // Key is the raw value of a KV key.
    // Value is every SeqNo which talks about that key.
    // This entire structure should be shardable, so we can dump it to disk!
    std::unordered_map<std::vector<uint8_t>, SeqNoCollection> seqnos_by_key;

  public:
    SeqnosByKey(const std::string& table_name) :
      Strategy(fmt::format("SeqnosByKey for table {}", table_name))
    {}

    void handle_committed_transaction(
      const ccf::TxID& tx_id, const StorePtr& store) override
    {
      // TODO: Find target table in this store, catalog every key it writes
    }

    // // TODO: Serialisation of key, ideally happened already?
    // SeqNoCollection get_write_txs(key) {}
  };
}