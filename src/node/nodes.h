// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "entities.h"
#include "kv/kvtypes.h"
#include "nodeinfonetwork.h"

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

DECLARE_JSON_ENUM(
  ConsensusType,
  {{ConsensusType::Raft, "Raft"}, {ConsensusType::Pbft, "Pbft"}});

MSGPACK_ADD_ENUM(ConsensusType);

namespace ccf
{
  struct NodeInfo : NodeInfoNetwork
  {
    std::vector<uint8_t> cert;
    std::vector<uint8_t> quote;
    std::vector<uint8_t> encryption_pub_key;
    ConsensusType consensus_type;
    NodeStatus status = NodeStatus::PENDING;

    MSGPACK_DEFINE(
      MSGPACK_BASE(NodeInfoNetwork),
      cert,
      quote,
      encryption_pub_key,
      consensus_type,
      status);
  };
  DECLARE_JSON_TYPE_WITH_BASE(NodeInfo, NodeInfoNetwork);
  DECLARE_JSON_REQUIRED_FIELDS(
    NodeInfo, cert, quote, encryption_pub_key, consensus_type, status);

  using Nodes = Store::Map<NodeId, NodeInfo>;
}

FMT_BEGIN_NAMESPACE
template <>
struct formatter<ccf::NodeStatus>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const ccf::NodeStatus& state, FormatContext& ctx)
    -> decltype(ctx.out())
  {
    switch (state)
    {
      case (ccf::NodeStatus::PENDING):
      {
        return format_to(ctx.out(), "PENDING");
      }
      case (ccf::NodeStatus::TRUSTED):
      {
        return format_to(ctx.out(), "TRUSTED");
      }
      case (ccf::NodeStatus::RETIRED):
      {
        return format_to(ctx.out(), "RETIRED");
      }
    }
  }
};
FMT_END_NAMESPACE
