// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/indexing/strategy.h"
#include "ccf/node_subsystem_interface.h"
#include "ccf/pal/locking.h"

#include <map>
#include <memory>
#include <set>

namespace ccf::indexing
{
  // This base class simply manages a collection of indexing strategies. The
  // implementation will pass each committed transaction in-order to each
  // installed strategy. Applications should install strategies at
  // construction, and then retrieve those strategies and query them for indexed
  // results during endpoint execution.
  class IndexingStrategies : public ccf::AbstractNodeSubSystem
  {
  protected:
    ccf::pal::Mutex lock;
    std::set<StrategyPtr> strategies;

  public:
    virtual ~IndexingStrategies() = default;

    static char const* get_subsystem_name()
    {
      return "IndexingStrategies";
    }

    bool install_strategy(const StrategyPtr& strategy)
    {
      if (strategy == nullptr)
      {
        throw std::logic_error("Tried to install null strategy");
      }

      std::lock_guard<ccf::pal::Mutex> guard(lock);
      return strategies.insert(strategy).second;
    }

    void uninstall_strategy(const StrategyPtr& strategy)
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      if (strategy == nullptr || strategies.find(strategy) == strategies.end())
      {
        throw std::logic_error("Strategy doesn't exist");
      }

      strategies.erase(strategy);
    }

    nlohmann::json describe()
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      auto j = nlohmann::json::array();

      for (const auto& strategy : strategies)
      {
        j.push_back(strategy->describe());
      }

      return j;
    }
  };
}