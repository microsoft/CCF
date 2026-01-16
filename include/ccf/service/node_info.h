// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/ds/json.h"
#include "ccf/ds/quote_info.h"
#include "ccf/kv/version.h"
#include "ccf/service/local_sealing.h"
#include "ccf/service/node_info_network.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <optional>

namespace ccf
{
  enum class NodeStatus : uint8_t
  {
    PENDING = 0,
    TRUSTED = 1,
    RETIRED = 2
  };
  DECLARE_JSON_ENUM(
    NodeStatus,
    {{NodeStatus::PENDING, "Pending"},
     {NodeStatus::TRUSTED, "Trusted"},
     {NodeStatus::RETIRED, "Retired"}});

  struct NodeInfo : NodeInfoNetwork
  {
    /// Node enclave quote
    QuoteInfo quote_info;
    /// Node encryption public key, used to distribute ledger re-keys.
    ccf::crypto::Pem encryption_pub_key;
    /// Node status
    NodeStatus status = NodeStatus::PENDING;

    /** Set to the seqno of the latest ledger secret at the time the node is
        trusted */
    std::optional<ccf::kv::Version> ledger_secret_seqno = std::nullopt;

    /// Code identity for the node
    std::optional<std::string> code_digest = std::nullopt;

    /**
     *  Fields below are added in 2.x
     */

    /// Node certificate signing request
    std::optional<ccf::crypto::Pem> certificate_signing_request = std::nullopt;

    /// Public key
    std::optional<ccf::crypto::Pem> public_key = std::nullopt;

    /// Free-form user data, can be used to store operator correlation
    /// IDs/labels for the node for example
    nlohmann::json node_data = nullptr;

    /**
     * Fields below are deprecated
     */

    /** Deprecated as of 2.x.
     * Node certificate. Only set for 1.x releases. Further releases record
     * node identity in `public_key` field. Service-endorsed certificate is
     * recorded in "public:ccf.nodes.endorsed_certificates" table */
    std::optional<ccf::crypto::Pem> cert = std::nullopt;

    /** Commit state for Retired state
     *
     * Introduced during 2.x (2.0.5), and so optional for backward
     * compatibility.
     */
    bool retired_committed = false;

    std::optional<SealedRecoveryKey> sealed_recovery_key = std::nullopt;
  };
  DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(NodeInfo, NodeInfoNetwork);
  DECLARE_JSON_REQUIRED_FIELDS(
    NodeInfo, quote_info, encryption_pub_key, status);
  DECLARE_JSON_OPTIONAL_FIELDS(
    NodeInfo,
    cert,
    ledger_secret_seqno,
    code_digest,
    certificate_signing_request,
    public_key,
    node_data,
    retired_committed,
    sealed_recovery_key);
}

FMT_BEGIN_NAMESPACE
template <>
struct formatter<ccf::NodeStatus>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const ccf::NodeStatus& state, FormatContext& ctx) const
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
