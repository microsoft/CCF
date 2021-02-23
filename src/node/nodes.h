// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "entities.h"
#include "kv/map.h"
#include "node_info_network.h"
#include "quote_info.h"

#include <msgpack/msgpack.hpp>
#include <string>
#include <vector>

namespace ccf
{
  using NodeId =
    std::string; // < Hex-encoded hash of node's identity public key

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
  struct NodeInfo : NodeInfoNetwork
  {
    crypto::Pem cert;
    QuoteInfo quote_info;
    crypto::Pem encryption_pub_key;
    NodeStatus status = NodeStatus::PENDING;

    // Set to the seqno of the latest ledger secret at the time the node is
    // trusted
    std::optional<kv::Version> ledger_secret_seqno = std::nullopt;

    MSGPACK_DEFINE(
      MSGPACK_BASE(NodeInfoNetwork),
      cert,
      quote_info,
      encryption_pub_key,
      status,
      ledger_secret_seqno);
  };
  DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(NodeInfo, NodeInfoNetwork);
  DECLARE_JSON_REQUIRED_FIELDS(
    NodeInfo, cert, quote_info, encryption_pub_key, status);
  DECLARE_JSON_OPTIONAL_FIELDS(NodeInfo, ledger_secret_seqno);

  using Nodes = kv::Map<NodeId, NodeInfo>;
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
