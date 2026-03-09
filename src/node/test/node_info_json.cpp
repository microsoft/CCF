// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/logger.h"
#include "ccf/service/node_info_network.h"

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
  std::tie(v1.rpchost, v1.rpcport) = ccf::split_net_address(rpc_a);
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
    REQUIRE(
      new_converted.node_to_node_interface.bind_address ==
      ccf::NodeInfoNetwork::NetAddress(v1.nodehost + ":" + v1.nodeport));
    REQUIRE(
      new_converted.node_to_node_interface.published_address ==
      ccf::NodeInfoNetwork::NetAddress(v1.nodehost + ":" + v1.nodeport));

    REQUIRE(new_converted.rpc_interfaces.size() == 1);
    const auto& primary_rpc_it =
      new_converted.rpc_interfaces.find(ccf::PRIMARY_RPC_INTERFACE);
    const auto& primary_rpc = primary_rpc_it->second;
    REQUIRE(
      primary_rpc.bind_address ==
      ccf::NodeInfoNetwork::NetAddress(v1.rpchost + ":" + v1.rpcport));
    REQUIRE(
      primary_rpc.published_address ==
      ccf::NodeInfoNetwork::NetAddress(v1.pubhost + ":" + v1.pubport));
  }

  // Test that slightly malformed v2 JSON does not get misparsed as v1
  // and triggers an exception instead, for example when an unknown
  // operator feature is present
  {
    INFO("Malformed new format does not get misparsed as old format");
    nlohmann::json j = current;
    // Inject an unknown operator feature to make the JSON invalid for v2
    j["node_to_node_interface"]["enabled_operator_features"].push_back(
      "UnknownFeature");

    REQUIRE_THROWS_AS(j.get<ccf::NodeInfoNetwork>(), ccf::JsonParseError);
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
      auto& v_ = v;
      const auto it = j.find(k);
      REQUIRE(it != j.end());
      REQUIRE(it.value() == v_);
    }
  }
}