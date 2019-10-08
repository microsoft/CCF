// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "network_mock_tcp.h"

INetwork* Create_Mock_TCP_Network()
{
  return new MockTCPNetwork();
}

std::vector<uint8_t> MockTCPNetwork::_pending_msg;
MockTCPNetwork::Socket MockTCPNetwork::_socket(1);
std::vector<std::vector<uint8_t>> MockTCPNetwork::Socket::messages;
