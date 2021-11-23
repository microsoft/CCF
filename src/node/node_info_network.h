// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ds/json.h"

#include <string>

namespace ccf
{
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

  struct NodeInfoNetwork_v2
  {
    struct NetAddress
    {
      std::string hostname;
      std::string port;

      bool operator==(const NetAddress& other) const
      {
        return hostname == other.hostname && port == other.port;
      }
    };

    struct RpcAddresses
    {
      NetAddress bind_address;
      NetAddress published_address;

      std::optional<size_t> max_open_sessions_soft = std::nullopt;
      std::optional<size_t> max_open_sessions_hard = std::nullopt;

      bool operator==(const RpcAddresses& other) const
      {
        return bind_address == other.bind_address &&
          published_address == other.published_address &&
          max_open_sessions_soft == other.max_open_sessions_soft &&
          max_open_sessions_hard && other.max_open_sessions_hard;
      }
    };

    NetAddress node_address;
    std::vector<RpcAddresses> rpc_interfaces;
  };
  DECLARE_JSON_TYPE(NodeInfoNetwork_v2::NetAddress);
  DECLARE_JSON_REQUIRED_FIELDS(NodeInfoNetwork_v2::NetAddress, hostname, port);
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(NodeInfoNetwork_v2::RpcAddresses);
  DECLARE_JSON_REQUIRED_FIELDS(NodeInfoNetwork_v2::RpcAddresses, bind_address);
  DECLARE_JSON_OPTIONAL_FIELDS(
    NodeInfoNetwork_v2::RpcAddresses,
    max_open_sessions_soft,
    max_open_sessions_hard,
    published_address);
  DECLARE_JSON_TYPE(NodeInfoNetwork_v2);
  DECLARE_JSON_REQUIRED_FIELDS(
    NodeInfoNetwork_v2, node_address, rpc_interfaces);

  struct NodeInfoNetwork : public NodeInfoNetwork_v2
  {
    NodeInfoNetwork() = default;
    NodeInfoNetwork(const NodeInfoNetwork_v2& other) : NodeInfoNetwork_v2(other)
    {}

    bool operator==(const NodeInfoNetwork& other) const
    {
      return node_address == other.node_address &&
        rpc_interfaces == other.rpc_interfaces;
    }
  };

  // The JSON representation of a NodeInfoNetwork is the union of a
  // NodeInfoNetwork_v1 and a NodeInfoNetwork_v2. It contains the fields of
  // both, so can be read as (or from!) either
  inline void to_json(nlohmann::json& j, const NodeInfoNetwork& nin)
  {
    {
      NodeInfoNetwork_v1 v1;
      v1.nodehost = nin.node_address.hostname;
      v1.nodeport = nin.node_address.port;

      if (nin.rpc_interfaces.size() > 0)
      {
        const auto& primary_interface = nin.rpc_interfaces[0];
        v1.rpchost = primary_interface.bind_address.hostname;
        v1.rpcport = primary_interface.bind_address.port;
        v1.pubhost = primary_interface.published_address.hostname;
        v1.pubport = primary_interface.published_address.port;
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

      nin.node_address.hostname = v1.nodehost;
      nin.node_address.port = v1.nodeport;

      NodeInfoNetwork::RpcAddresses primary_interface;
      primary_interface.bind_address.hostname = v1.rpchost;
      primary_interface.bind_address.port = v1.rpcport;
      primary_interface.published_address.hostname = v1.pubhost;
      primary_interface.published_address.port = v1.pubport;

      nin.rpc_interfaces.emplace_back(std::move(primary_interface));
    }
  }
}