// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "../kv/kvtypes.h"
#include "entities.h"
#include "rpc/jsonrpc.h"

#include <msgpack.hpp>
#include <string>
#include <vector>

namespace ccf
{
  enum class NodeStatus
  {
    PENDING = 0,
    TRUSTED = 1,
    RETIRED = 2
  };
  DECLARE_JSON_ENUM(
    NodeStatus,
    {{NodeStatus::PENDING, "PENDING"},
     {NodeStatus::TRUSTED, "TRUSTED"},
     {NodeStatus::RETIRED, "RETIRED"}});
}

MSGPACK_ADD_ENUM(ccf::NodeStatus);

namespace ccf
{
  struct NodeInfo
  {
    std::string host;
    std::string pubhost;
    std::string raftport;
    std::string tlsport;
    std::vector<uint8_t> cert;
    std::vector<uint8_t> quote;
    NodeStatus status = NodeStatus::PENDING;

    MSGPACK_DEFINE(host, pubhost, raftport, tlsport, cert, quote, status);
  };
  DECLARE_REQUIRED_JSON_FIELDS(
    NodeInfo, host, pubhost, raftport, tlsport, cert, quote, status)

  using Nodes = Store::Map<NodeId, NodeInfo>;
}
