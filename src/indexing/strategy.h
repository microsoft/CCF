// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx_id.h"

#include <memory>
#include <string>

namespace indexing
{
  class Strategy
  {
    const std::string name;

  public:
    Strategy(const std::string& name) : name(name) {}
    virtual ~Strategy() = default;

    std::string get_name() const
    {
      return name;
    }

    // Receives every committed transaction, in-order
    virtual void append_committed_transaction(
      const ccf::TxID& tx_id, const uint8_t* data, size_t size) = 0;

    // I think some strategies need this, so the indexer should tick them?
    virtual void tick() {}
  };

  using StrategyPtr = std::unique_ptr<Strategy>;

  // TODO: This should be elsewhere
  // class IndexSeqNoPerKey : public IndexingStrategy
  // {
  // public:
  //   IndexSeqNoPerKey(table_name) {}

  //   // TODO: Serialisation of key, ideally happened already?
  //   SeqNoCollection get_write_txs(key) {}
  // };
}