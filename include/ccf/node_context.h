// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/historical_queries_interface.h"
#include "ccf/indexing/indexer_interface.h"
#include "ccf/node_subsystem_interface.h"

namespace ccfapp
{
  struct AbstractNodeContext
  {
  protected:
    std::map<std::string, std::shared_ptr<ccf::AbstractNodeSubSystem>>
      subsystems;

    void install_subsystem(
      const std::shared_ptr<ccf::AbstractNodeSubSystem>& subsystem,
      const std::string& name)
    {
      if (subsystem == nullptr)
      {
        return;
      }

      const auto it = subsystems.find(name);
      if (it != subsystems.end())
      {
        throw std::logic_error(
          fmt::format("Already registered subsystem {}", name));
      }

      subsystems.emplace_hint(it, name, subsystem);
    }

    template <typename T>
    std::shared_ptr<T> get_subsystem(const std::string& name) const
    {
      const auto it = subsystems.find(name);
      if (it != subsystems.end())
      {
        // NB: May still be nullptr, if it->second.get() is not a T*
        return std::dynamic_pointer_cast<T>(it->second);
      }

      return nullptr;
    }

  public:
    virtual ~AbstractNodeContext() = default;

    template <typename T>
    void install_subsystem(const std::shared_ptr<T>& subsystem)
    {
      install_subsystem(subsystem, T::get_subsystem_name());
    }

    template <typename T>
    std::shared_ptr<T> get_subsystem() const
    {
      return get_subsystem<T>(T::get_subsystem_name());
    }

    virtual ccf::NodeId get_node_id() const
    {
      return {};
    }

    virtual crypto::Pem get_self_signed_certificate() const
    {
      return {};
    }

    ccf::historical::AbstractStateCache& get_historical_state()
    {
      auto historical_state_cache =
        get_subsystem<ccf::historical::AbstractStateCache>();
      if (historical_state_cache == nullptr)
      {
        throw std::logic_error(
          "Calling get_historical_state before subsystem is installed");
      }
      return *historical_state_cache;
    }

    ccf::indexing::IndexingStrategies& get_indexing_strategies()
    {
      auto indexer = get_subsystem<ccf::indexing::IndexingStrategies>();
      if (indexer == nullptr)
      {
        throw std::logic_error(
          "Calling get_indexing_strategies before subsystem is installed");
      }
      return *indexer;
    }
  };
}
