// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx_id.h"
#include "crypto/pem.h"
#include "node/node_info_network.h"
#include "node/quote_info.h"

namespace ccf
{
  enum class NodeStatus
  {
    PENDING = 0,
    TRUSTED = 1,
    RETIRED = 2,
    CATCHING_UP = 3,
    RETIRING = 4,
  };
  DECLARE_JSON_ENUM(
    NodeStatus,
    {{NodeStatus::PENDING, "Pending"},
     {NodeStatus::TRUSTED, "Trusted"},
     {NodeStatus::RETIRED, "Retired"},
     {NodeStatus::CATCHING_UP, "CatchingUp"},
     {NodeStatus::RETIRING, "Retiring"}});

  struct NodeInfo : NodeInfoNetwork
  {
    /// Node certificate
    crypto::Pem cert;
    /// Node enclave quote
    QuoteInfo quote_info;
    /// Node encryption public key, used to distribute ledger re-keys.
    crypto::Pem encryption_pub_key;
    /// Node status
    NodeStatus status = NodeStatus::PENDING;

    /** Set to the seqno of the latest ledger secret at the time the node is
        trusted */
    std::optional<ccf::SeqNo> ledger_secret_seqno = std::nullopt;
  };

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
      case (ccf::NodeStatus::CATCHING_UP):
      {
        return format_to(ctx.out(), "CATCHING_UP");
      }
      case (ccf::NodeStatus::TRUSTED):
      {
        return format_to(ctx.out(), "TRUSTED");
      }
      case (ccf::NodeStatus::RETIRING):
      {
        return format_to(ctx.out(), "RETIRING");
      }
      case (ccf::NodeStatus::RETIRED):
      {
        return format_to(ctx.out(), "RETIRED");
      }
    }
  }
};
FMT_END_NAMESPACE
