// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "interface.h"
#include "node/entities.h"
#include "rpchandler.h"

namespace enclave
{
  class RPCMap
  {
  private:
    std::unordered_map<uint8_t, std::shared_ptr<RpcHandler>> map;
    std::map<std::string, ccf::ActorsType> actors_map;

  public:
    RPCMap() = default;

    template <ccf::ActorsType T>
    auto register_frontend(
      std::string name, std::shared_ptr<RpcHandler> handler_)
    {
      actors_map.emplace(name, T);
      auto h = map.emplace(T, handler_);
      return h.first->second;
    }

    ccf::ActorsType resolve(std::string& name)
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

  inline void initialize_frontend(
    std::shared_ptr<enclave::RpcHandler> fe,
    const CCFConfig::SignatureIntervals& sig_intervals,
    std::shared_ptr<AbstractForwarder> cmd_forwarder)
  {
    fe->set_sig_intervals(sig_intervals.sig_max_tx, sig_intervals.sig_max_ms);
    fe->set_cmd_forwarder(cmd_forwarder);
  }
}