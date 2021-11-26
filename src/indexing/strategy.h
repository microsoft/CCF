// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx_id.h"
#include "kv/store.h"

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
    virtual void handle_committed_transaction(
      const ccf::TxID& tx_id, const std::shared_ptr<kv::Store>& store) = 0;

    // I think some strategies need this, so the indexer should tick them?
    virtual void tick() {}
  };

  using StrategyPtr = std::unique_ptr<Strategy>;
}