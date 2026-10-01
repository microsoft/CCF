// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/actors.h"
#include "rpc_handler.h"

namespace ccf
{
  class RPCMap
  {
  private:
    std::unordered_map<ccf::ActorsType, std::shared_ptr<ccf::RpcHandler>> map;
    std::map<std::string, ccf::ActorsType> actors_map;

  public:
    RPCMap() = default;

    template <ccf::ActorsType T>
    void register_frontend(std::shared_ptr<RpcHandler> handler_)
    {
      const auto* const name = get_actor_prefix(T);
      actors_map.emplace(name, T);
      map.emplace(T, handler_);
    }

    ccf::ActorsType resolve(const std::string& name)
    {
      auto search = actors_map.find(name);
      if (search == actors_map.end())
      {
        return ccf::ActorsType::unknown;
      }

      return search->second;
    }

    std::optional<std::shared_ptr<RpcHandler>> find(ccf::ActorsType index)
    {
      auto search = map.find(index);
      if (search == map.end())
      {
        return {};
      }

      return search->second;
    }

    auto& frontends()
    {
      return map;
    }
  };
}