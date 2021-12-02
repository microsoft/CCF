// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/indexing/strategy.h"

#include <map>
#include <memory>
#include <string>

namespace ccf::indexing
{
  // An abstract Indexer manages a collection of strategies. The implementation
  // will pass each committed transaction in-order to each registered strategy.
  // Applications should install strategies at construction, and then retrieve
  // those strategies and query them for indexed results during endpoint
  // execution.
  class AbstractIndexer
  {
  protected:
    // Store the highest TxID that each strategy has been given, and assume it
    // doesn't need to be given again later.
    using StrategyContext = std::pair<ccf::TxID, StrategyPtr>;
    std::map<std::string, StrategyContext> strategies;

  public:
    virtual ~AbstractIndexer() = default;

    std::string install_strategy(StrategyPtr&& strategy)
    {
      if (strategy == nullptr)
      {
        throw std::logic_error("Tried to install null strategy");
      }

      const auto name = strategy->get_name();

      auto it = strategies.find(name);
      if (it != strategies.end())
      {
        throw std::logic_error(
          fmt::format("Strategy named {} already exists", name));
      }

      strategies.emplace_hint(
        it, name, std::make_pair(ccf::TxID{}, std::move(strategy)));

      return name;
    }

    template <typename T>
    T* get_strategy(const std::string& name)
    {
      auto it = strategies.find(name);
      if (it != strategies.end())
      {
        auto t = dynamic_cast<T*>(it->second.second.get());
        return t;
      }

      return nullptr;
    }
  };
}