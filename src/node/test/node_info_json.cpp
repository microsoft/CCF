// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/node_info_network.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

TEST_CASE("Multiple versions of NodeInfo")
{
  ccf::NodeInfoNetwork::NetAddress node{"42.42.42.42", "4242"};
  ccf::NodeInfoNetwork::NetAddress rpc_a{"1.2.3.4", "4321"};
  ccf::NodeInfoNetwork::NetAddress rpc_a_pub{"5.6.7.8", "8765"};
  ccf::NodeInfoNetwork::NetAddress rpc_b{"1.2.3.4", "4444"};
  ccf::NodeInfoNetwork::NetAddress rpc_b_pub{"5.6.7.8", "8888"};

  ccf::NodeInfoNetwork current;
  current.node_address = node;
  current.rpc_interfaces.push_back(
    ccf::NodeInfoNetwork::RpcAddresses{rpc_a, rpc_a_pub, 100, 200});
  current.rpc_interfaces.push_back(
    ccf::NodeInfoNetwork::RpcAddresses{rpc_b, rpc_b_pub, 300, 400});

  ccf::NodeInfoNetwork_v1 v1;
  v1.nodehost = node.hostname;
  v1.nodeport = node.port;
  v1.rpchost = rpc_a.hostname;
  v1.rpcport = rpc_a.port;
  v1.pubhost = rpc_b.hostname;
  v1.pubport = rpc_b.port;

  {
    INFO("Current format can be converted to and from JSON");
    nlohmann::json j = current;
    const auto converted = j.get<ccf::NodeInfoNetwork>();
    REQUIRE(current == converted);
  }

  {
    INFO("Old format survives round-trip through current");
    nlohmann::json j = v1;
    const auto intermediate = j.get<ccf::NodeInfoNetwork>();
    nlohmann::json j2 = intermediate;
    const auto converted = j2.get<ccf::NodeInfoNetwork_v1>();

    // Manual equality check - not implementing it now for a deprecated format
    REQUIRE(v1.nodehost == converted.nodehost);
    REQUIRE(v1.nodeport == converted.nodeport);
    REQUIRE(v1.rpchost == converted.rpchost);
    REQUIRE(v1.rpcport == converted.rpcport);
    REQUIRE(v1.pubhost == converted.pubhost);
    REQUIRE(v1.pubport == converted.pubport);
  }

  {
    INFO(
      "Current format loses some information when round-tripping through old");
    nlohmann::json j = current;
    const auto intermediate = j.get<ccf::NodeInfoNetwork_v1>();
    nlohmann::json j2 = intermediate;
    const auto converted = j2.get<ccf::NodeInfoNetwork>();
    REQUIRE(!(current == converted));

    // The node information has been kept
    REQUIRE(current.node_address == converted.node_address);

    // The first RPC interface has kept its addresses, though lost its sessions
    // caps
    REQUIRE(converted.rpc_interfaces.size() > 0);
    const auto& current_interface = current.rpc_interfaces[0];
    const auto& converted_interface = converted.rpc_interfaces[0];
    REQUIRE(current_interface.bind_address == converted_interface.bind_address);
    REQUIRE(
      current_interface.published_address ==
      converted_interface.published_address);
    REQUIRE(
      current_interface.max_open_sessions_hard !=
      converted_interface.max_open_sessions_hard);
    REQUIRE(
      current_interface.max_open_sessions_soft !=
      converted_interface.max_open_sessions_soft);

    // The second RPC interface has been lost
    REQUIRE(converted.rpc_interfaces.size() == 1);
    REQUIRE(converted.rpc_interfaces.size() < current.rpc_interfaces.size());
  }

  {
    INFO("Old format survives round-trip through new");
    nlohmann::json j = current;
    const auto intermediate = j.get<ccf::NodeInfoNetwork_v2>();
    nlohmann::json j2 = intermediate;
    const auto converted = j2.get<ccf::NodeInfoNetwork>();

    REQUIRE(current == converted);

    // Implementation detail: The reason this works is that the new format's
    // JSON representation is a strict subset of the combined JSON document
    // produced by the current format
    for (const auto& [k, v] : j2.items())
    {
      const auto it = j.find(k);
      REQUIRE(it != j.end());
      REQUIRE(it.value() == v);
    }
  }
}