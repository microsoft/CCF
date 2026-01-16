// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/service/node_info_network.h"
#include "ds/internal_logger.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

TEST_CASE("Multiple versions of NodeInfoNetwork")
{
  ccf::NodeInfoNetwork::NetAddress node{"42.42.42.42:4242"};
  ccf::NodeInfoNetwork::NetAddress rpc_a{"1.2.3.4:4321"};
  ccf::NodeInfoNetwork::NetAddress rpc_a_pub{"5.6.7.8:8765"};
  ccf::NodeInfoNetwork::NetAddress rpc_b{"1.2.3.4:4444"};
  ccf::NodeInfoNetwork::NetAddress rpc_b_pub{"5.6.7.8:8888"};

  static constexpr auto first_rpc_name = "first";
  static constexpr auto second_rpc_name = "second";

  ccf::NodeInfoNetwork current;
  current.node_to_node_interface.bind_address = node;
  current.rpc_interfaces.emplace(
    first_rpc_name,
    ccf::NodeInfoNetwork::NetInterface{
      rpc_a, rpc_a_pub, "tcp", "HTTP1", 100, 200});
  current.rpc_interfaces.emplace(
    second_rpc_name,
    ccf::NodeInfoNetwork::NetInterface{
      rpc_b, rpc_b_pub, "udp", "HTTP2", 300, 400});

  ccf::NodeInfoNetwork_v1 v1;
  std::tie(v1.nodehost, v1.nodeport) = ccf::split_net_address(node);
  std::tie(v1.rpchost, v1.nodeport) = ccf::split_net_address(rpc_a);
  std::tie(v1.pubhost, v1.pubport) = ccf::split_net_address(rpc_b);

  {
    INFO("Current format can be converted to and from JSON");
    nlohmann::json j = current;
    const auto converted = j.get<ccf::NodeInfoNetwork>();
    REQUIRE(current == converted);
  }

  // No longer true, to_json NEVER writes v1 fields now
  // Because no legitimate current node should be using v1 anymore
  // {
  //   INFO("Old format survives round-trip through current");
  //   nlohmann::json j = v1;
  //   const auto intermediate = j.get<ccf::NodeInfoNetwork>();
  //   nlohmann::json j2 = intermediate;
  //   const auto converted = j2.get<ccf::NodeInfoNetwork_v1>();

  //   // Manual equality check - not implementing it now for a deprecated
  //   format REQUIRE(v1.nodehost == converted.nodehost); REQUIRE(v1.nodeport ==
  //   converted.nodeport); REQUIRE(v1.rpchost == converted.rpchost);
  //   REQUIRE(v1.rpcport == converted.rpcport);
  //   REQUIRE(v1.pubhost == converted.pubhost);
  //   REQUIRE(v1.pubport == converted.pubport);
  // }

  // No longer true, to_json NEVER writes v1 fields now,
  // So the current format cannot be read as v1 anymore
  // {
  //   INFO(
  //     "Current format loses some information when round-tripping through
  //     old");
  //   nlohmann::json j = current;
  //   const auto intermediate = j.get<ccf::NodeInfoNetwork_v1>();
  //   nlohmann::json j2 = intermediate;
  //   const auto converted = j2.get<ccf::NodeInfoNetwork>();
  //   REQUIRE(!(current == converted));

  //   // The node information has been kept
  //   REQUIRE(current.node_to_node_interface ==
  //   converted.node_to_node_interface);

  //   // Only the _first_ RPC interface has kept its addresses, though lost its
  //   // sessions caps
  //   REQUIRE(converted.rpc_interfaces.size() > 0);

  //   const auto& current_interface = current.rpc_interfaces.begin()->second;
  //   const auto& converted_interface =
  //     converted.rpc_interfaces.at(ccf::PRIMARY_RPC_INTERFACE);

  //   REQUIRE(current_interface.bind_address ==
  //   converted_interface.bind_address); REQUIRE(
  //     current_interface.published_address ==
  //     converted_interface.published_address);
  //   REQUIRE(
  //     current_interface.max_open_sessions_hard !=
  //     converted_interface.max_open_sessions_hard);
  //   REQUIRE(
  //     current_interface.max_open_sessions_soft !=
  //     converted_interface.max_open_sessions_soft);

  //   // The second RPC interface has been lost
  //   REQUIRE(converted.rpc_interfaces.size() == 1);
  //   REQUIRE(converted.rpc_interfaces.size() < current.rpc_interfaces.size());
  // }

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
      auto& v_ = v;
      const auto it = j.find(k);
      REQUIRE(it != j.end());
      REQUIRE(it.value() == v_);
    }
  }
}