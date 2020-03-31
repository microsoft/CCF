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

  public:
    RPCMap() = default;

    template <ccf::ActorsType T>
    void register_frontend(
      std::string name, std::shared_ptr<RpcHandler> handler_)
    {
      actors_map.emplace(name, T);
      map.emplace(T, handler_);
    }

    ccf::ActorsType resolve(const std::string& name)
    {
      auto search = actors_map.find(name);
      if (search == actors_map.end())
        return ccf::ActorsType::unknown;

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

#define REGISTER_FRONTEND(rpc_map, name, fe) \
  rpc_map->register_frontend<ccf::ActorsType::name>(#name, fe)
}