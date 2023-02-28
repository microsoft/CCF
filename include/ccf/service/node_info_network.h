// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/ds/json.h"
#include "ccf/ds/nonstd.h"
#include "ccf/http_configuration.h"
#include "ccf/service/acme_client_config.h"

#include <string>

namespace ccf
{
  enum class Authority
  {
    NODE,
    SERVICE,
    ACME,
    UNSECURED
  };
  DECLARE_JSON_ENUM(
    Authority,
    {{Authority::NODE, "Node"},
     {Authority::SERVICE, "Service"},
     {Authority::ACME, "ACME"},
     {Authority::UNSECURED, "Unsecured"}});

  enum class ApplicationProtocol
  {
    HTTP1,
    HTTP2
  };
  DECLARE_JSON_ENUM(
    ApplicationProtocol,
    {{ApplicationProtocol::HTTP1, "HTTP1"},
     {ApplicationProtocol::HTTP2, "HTTP2"}});

  struct Endorsement
  {
    Authority authority;

    std::optional<std::string> acme_configuration;

    bool operator==(const Endorsement& other) const
    {
      return authority == other.authority &&
        acme_configuration == other.acme_configuration;
    }
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Endorsement);
  DECLARE_JSON_REQUIRED_FIELDS(Endorsement, authority);
  DECLARE_JSON_OPTIONAL_FIELDS(Endorsement, acme_configuration);

  struct NodeInfoNetwork_v1
  {
    std::string rpchost;
    std::string pubhost;
    std::string nodehost;
    std::string nodeport;
    std::string rpcport;
    std::string pubport;
  };
  DECLARE_JSON_TYPE(NodeInfoNetwork_v1);
  DECLARE_JSON_REQUIRED_FIELDS(
    NodeInfoNetwork_v1, rpchost, pubhost, nodehost, nodeport, rpcport, pubport);

  static constexpr auto PRIMARY_RPC_INTERFACE = "ccf.default_rpc_interface";

  /// Node network information
  struct NodeInfoNetwork_v2
  {
    using NetAddress = std::string;
    using RpcInterfaceID = std::string;
    using NetProtocol = std::string;

    /// Network interface description
    struct NetInterface
    {
      NetAddress bind_address;
      NetAddress published_address;
      NetProtocol protocol;
      std::optional<ApplicationProtocol> app_protocol = std::nullopt;

      /// Maximum open sessions soft limit
      std::optional<size_t> max_open_sessions_soft = std::nullopt;

      /// Maximum open sessions hard limit
      std::optional<size_t> max_open_sessions_hard = std::nullopt;

      /// HTTP configuration
      std::optional<http::ParserConfiguration> http_configuration =
        std::nullopt;

      /// Interface endorsement
      std::optional<Endorsement> endorsement = std::nullopt;

      /// Regular expressions of endpoints that are accessible over
      /// this interface. std::nullopt means everything is accepted.
      std::optional<std::vector<std::string>> accepted_endpoints = std::nullopt;

      /// Timeout for forwarded RPC calls (in milliseconds)
      std::optional<size_t> forwarding_timeout = std::nullopt;

      bool operator==(const NetInterface& other) const
      {
        return bind_address == other.bind_address &&
          published_address == other.published_address &&
          protocol == other.protocol && app_protocol == other.app_protocol &&
          max_open_sessions_soft == other.max_open_sessions_soft &&
          max_open_sessions_hard == other.max_open_sessions_hard &&
          endorsement == other.endorsement &&
          http_configuration == other.http_configuration &&
          accepted_endpoints == other.accepted_endpoints &&
          forwarding_timeout == other.forwarding_timeout;
      }
    };

    /// RPC interface mapping
    using RpcInterfaces = std::map<RpcInterfaceID, NetInterface>;

    /// Node-to-node network interface
    NetInterface node_to_node_interface;

    /// RPC interfaces
    RpcInterfaces rpc_interfaces;

    /// ACME configuration description
    struct ACME
    {
      /// Mapping of ACME client configuration names to configurations
      std::map<std::string, ccf::ACMEClientConfig> configurations;

      bool operator==(const ACME&) const = default;
    };

    /// ACME configuration
    std::optional<ACME> acme = std::nullopt;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(NodeInfoNetwork_v2::NetInterface);
  DECLARE_JSON_REQUIRED_FIELDS(NodeInfoNetwork_v2::NetInterface, bind_address);
  DECLARE_JSON_OPTIONAL_FIELDS(
    NodeInfoNetwork_v2::NetInterface,
    endorsement,
    max_open_sessions_soft,
    max_open_sessions_hard,
    published_address,
    protocol,
    app_protocol,
    http_configuration,
    accepted_endpoints,
    forwarding_timeout);
  DECLARE_JSON_TYPE(NodeInfoNetwork_v2::ACME);
  DECLARE_JSON_REQUIRED_FIELDS(NodeInfoNetwork_v2::ACME, configurations);
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(NodeInfoNetwork_v2);
  DECLARE_JSON_REQUIRED_FIELDS(
    NodeInfoNetwork_v2, node_to_node_interface, rpc_interfaces);
  DECLARE_JSON_OPTIONAL_FIELDS(NodeInfoNetwork_v2, acme);

  struct NodeInfoNetwork : public NodeInfoNetwork_v2
  {
    NodeInfoNetwork() = default;
    NodeInfoNetwork(const NodeInfoNetwork_v2& other) : NodeInfoNetwork_v2(other)
    {}

    bool operator==(const NodeInfoNetwork& other) const
    {
      return node_to_node_interface == other.node_to_node_interface &&
        rpc_interfaces == other.rpc_interfaces;
    }
  };

  inline static std::pair<std::string, std::string> split_net_address(
    const NodeInfoNetwork::NetAddress& addr)
  {
    auto [host, port] = nonstd::rsplit_1(addr, ":");
    return std::make_pair(std::string(host), std::string(port));
  }

  inline static NodeInfoNetwork::NetAddress make_net_address(
    const std::string& host, const std::string& port)
  {
    return fmt::format("{}:{}", host, port);
  }

  // The JSON representation of a NodeInfoNetwork is the union of a
  // NodeInfoNetwork_v1 and a NodeInfoNetwork_v2. It contains the fields of
  // both, so can be read as (or from!) either
  inline void to_json(nlohmann::json& j, const NodeInfoNetwork& nin)
  {
    {
      NodeInfoNetwork_v1 v1;
      std::tie(v1.nodehost, v1.nodeport) =
        split_net_address(nin.node_to_node_interface.bind_address);

      if (nin.rpc_interfaces.size() > 0)
      {
        const auto& primary_interface = nin.rpc_interfaces.begin()->second;
        std::tie(v1.rpchost, v1.rpcport) =
          split_net_address(primary_interface.bind_address);
        std::tie(v1.pubhost, v1.pubport) =
          split_net_address(primary_interface.published_address);
      }
      to_json(j, v1);
    }

    to_json(j, (const NodeInfoNetwork_v2&)nin);
  }

  inline void from_json(const nlohmann::json& j, NodeInfoNetwork& nin)
  {
    try
    {
      NodeInfoNetwork_v2 v2;
      from_json(j, v2);
      nin = NodeInfoNetwork(v2);
    }
    catch (const JsonParseError& jpe)
    {
      NodeInfoNetwork_v1 v1;
      from_json(j, v1);

      nin.node_to_node_interface.bind_address =
        make_net_address(v1.nodehost, v1.nodeport);

      NodeInfoNetwork::NetInterface primary_interface;
      primary_interface.bind_address = make_net_address(v1.rpchost, v1.rpcport);
      primary_interface.published_address =
        make_net_address(v1.pubhost, v1.pubport);

      nin.rpc_interfaces.emplace(
        PRIMARY_RPC_INTERFACE, std::move(primary_interface));
    }
  }
}

FMT_BEGIN_NAMESPACE template <>
struct formatter<ccf::Authority>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const ccf::Authority& authority, FormatContext& ctx) const
    -> decltype(ctx.out())
  {
    switch (authority)
    {
      case (ccf::Authority::NODE):
      {
        return format_to(ctx.out(), "Node");
      }
      case (ccf::Authority::SERVICE):
      {
        return format_to(ctx.out(), "Service");
      }
      case (ccf::Authority::ACME):
      {
        return format_to(ctx.out(), "ACME");
      }
      case (ccf::Authority::UNSECURED):
      {
        return format_to(ctx.out(), "Unsecured");
      }
    }
  }
};
FMT_END_NAMESPACE
