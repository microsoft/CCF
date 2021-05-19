// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ds/json.h"

#include <string>

namespace ccf
{
  struct NodeInfoNetwork
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
      NetAddress rpc_address;
      NetAddress public_rpc_address;
    };

    NetAddress node_address;
    std::vector<RpcAddresses> rpc_interfaces;
  };
  DECLARE_JSON_TYPE(NodeInfoNetwork::NetAddress);
  DECLARE_JSON_REQUIRED_FIELDS(NodeInfoNetwork::NetAddress, hostname, port);
  DECLARE_JSON_TYPE(NodeInfoNetwork::RpcAddresses);
  DECLARE_JSON_REQUIRED_FIELDS(
    NodeInfoNetwork::RpcAddresses, rpc_address, public_rpc_address);
  DECLARE_JSON_TYPE(NodeInfoNetwork);
  DECLARE_JSON_REQUIRED_FIELDS(NodeInfoNetwork, node_address, rpc_interfaces);
}