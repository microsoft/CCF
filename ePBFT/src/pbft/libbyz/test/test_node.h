// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#pragma once
#include "Message.h"
#include "Node.h"
#include "network_mock.h"

TEST_CASE("Test Node")
{
  struct NodeExposer : Node
  {
    using Node::send_new_key;
  };

  std::vector<PrincipalInfo> principal_info;
  for (NodeId i = 0; i < 6; ++i)
  {
    PrincipalInfo pi = {
      i,
      (short)(3000 + i),
      "ip",
      "96031a6cbe405894f1c0295881bd3946f0215f95fc40b7f1f0cc89b821c58504",
      "8691c3438859c142a26b5f251b96f39a463799430315d34ce8a4db0d2638f751",
      "name-1",
      true};
    principal_info.emplace_back(pi);
  }
  GeneralInfo gi = {
    4, 2, 1, true, "generic", 1800000, 5000, 100, 9999250000, principal_info};

  NodeInfo node_info_0 = {
    gi.principal_info[0],
    "0045c65ec31179652c57ae97f50de77e177a939dce74e39d7db51740663afb69",
    gi};
  NodeInfo node_info_1 = {
    gi.principal_info[1],
    "d0c95c545e1eaff52216acfd5bcf0909b241f89894585a3e9008d57b07d6b05c",
    gi};

  Node node_0(node_info_0);
  node_0.init_network(std::unique_ptr<INetwork>(Create_Mock_Network()));

  for (auto& pi : gi.principal_info)
  {
    if (pi.id != node_info_0.own_info.id)
    {
      node_0.add_principal(pi);
    }
  }

  (node_0.*&NodeExposer::send_new_key)();

  Node node_1(node_info_1);
  node_1.init_network(std::unique_ptr<INetwork>(Create_Mock_Network()));

  for (auto& pi : gi.principal_info)
  {
    if (pi.id != node_info_1.own_info.id)
    {
      node_1.add_principal(pi);
    }
  }

  CHECK(node_1.has_messages(0));

  auto message = node_1.recv();
  std::cout << message->contents() << std::endl;

  CHECK(node_0.is_replica(0));
  CHECK(node_1.is_replica(0));

  delete message;
}
