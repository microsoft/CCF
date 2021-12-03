// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/indexing/strategy.h"

#include <map>
#include <memory>

namespace ccf::indexing
{
  // This base class simply manages a collection of indexing strategies. The
  // implementation will pass each committed transaction in-order to each
  // installed strategy. Applications should install strategies at
  // construction, and then retrieve those strategies and query them for indexed
  // results during endpoint execution.
  class IndexingStrategies
  {
  protected:
    // Store the highest TxID that each strategy has been given, and assume it
    // doesn't need to be given again later.
    std::map<StrategyPtr, ccf::TxID> strategies;

  public:
    virtual ~IndexingStrategies() = default;

    bool install_strategy(const StrategyPtr& strategy)
    {
      if (strategy == nullptr)
      {
        throw std::logic_error("Tried to install null strategy");
      }

      const auto it = strategies.find(strategy);
      if (it == strategies.end())
      {
        strategies.emplace_hint(it, strategy, ccf::TxID{});
        return true;
      }
      else
      {
        return false;
      }
    }
  };
}