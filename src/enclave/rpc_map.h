// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/entities.h"
#include "rpc_handler.h"

namespace enclave
{
  class RPCMap
  {
  private:
    std::unordered_map<ccf::ActorsType, std::shared_ptr<RpcHandler>> map;
    std::map<std::string, ccf::ActorsType> actors_map;
    std::map<ccf::ActorsType, std::string> preferred_names;

  public:
    RPCMap() = default;

    template <ccf::ActorsType T>
    void register_frontend(
      const std::vector<std::string>& redirect_names,
      std::shared_ptr<RpcHandler> handler_)
    {
      const auto name = get_actor_prefix(T);
      actors_map.emplace(name, T);
      preferred_names.emplace(T, name);
      for (const auto& redirect_name : redirect_names)
      {
        actors_map.emplace(redirect_name, T);
      }
      map.emplace(T, handler_);
    }

    ccf::ActorsType resolve(
      const std::string& name, std::string& preferred_name)
    {
      auto search = actors_map.find(name);
      if (search == actors_map.end())
        return ccf::ActorsType::unknown;

      auto reverse_it = preferred_names.find(search->second);
      if (reverse_it != preferred_names.end())
        preferred_name = reverse_it->second;

      return search->second;
    }

    std::optional<std::shared_ptr<RpcHandler>> find(ccf::ActorsType index)
    {
      auto search = map.find(index);
      if (search == map.end())
        return {};

      return search->second;
    }

    auto& get_map()
    {
      return map;
    }
  };
}