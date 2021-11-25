// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

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
    std::unordered_map<std::vector<uint8_t>, ccf::historical::SeqNoCollection>
      seqnos_by_key;

  public:
    SeqnosByKey(const std::string& table_name) :
      Strategy(fmt::format("SeqnosByKey for table {}", table_name))
    {}

    void append_committed_transaction(
      const ccf::TxID& tx_id, const uint8_t* data, size_t size) override
    {
      // TODO
      // Ah crud, of course the problem with this is that I need to track
      // historical secrets just like the historical system does, to deserialise
      // and verify, just like it does! So I should be relying on that
      // first.
      // Create a new store and try to deserialise this entry into it
      StorePtr store = std::make_shared<kv::Store>(
        false /* Do not start from very first seqno */,
        true /* Make use of historical secrets */);
    }

    // // TODO: Serialisation of key, ideally happened already?
    // SeqNoCollection get_write_txs(key) {}
  };
}