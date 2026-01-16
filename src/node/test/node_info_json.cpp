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

  // to_json(NodeInfoNetwork) NEVER writes v1 fields now
  // No current node should be using v1 anymore
  {
    INFO("Old format loses old fields when converted to new format");
    nlohmann::json j = v1;
    nlohmann::json converted;
    to_json(converted, j.get<ccf::NodeInfoNetwork>());
    const auto dumped_converted = converted.dump();
    const auto deserialized_converted = nlohmann::json::parse(dumped_converted);

    // v1 fields are not present anymore
    REQUIRE(!deserialized_converted.contains("nodehost"));
    REQUIRE(!deserialized_converted.contains("nodeport"));
    REQUIRE(!deserialized_converted.contains("rpchost"));
    REQUIRE(!deserialized_converted.contains("rpcport"));
    REQUIRE(!deserialized_converted.contains("pubhost"));
    REQUIRE(!deserialized_converted.contains("pubport"));

    const auto new_converted =
      deserialized_converted.get<ccf::NodeInfoNetwork>();

    // v2 fields have been constructed correctly
    REQUIRE(new_converted.node_to_node_interface.bind_address ==
            ccf::NodeInfoNetwork::NetAddress(
              v1.nodehost + ":" + v1.nodeport));
  }

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