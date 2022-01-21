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
    std::set<StrategyPtr> strategies;

  public:
    virtual ~IndexingStrategies() = default;

    bool install_strategy(const StrategyPtr& strategy)
    {
      if (strategy == nullptr)
      {
        throw std::logic_error("Tried to install null strategy");
      }

      return strategies.insert(strategy).second;
    }
  };
}