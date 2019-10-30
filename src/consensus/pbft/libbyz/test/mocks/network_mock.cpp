// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "network_mock.h"

INetwork* Create_Mock_Network()
{
  return new MockNetwork();
}

std::vector<uint8_t> MockNetwork::_pending_msg;
MockNetwork::Socket MockNetwork::_socket(1);
std::vector<std::vector<uint8_t>> MockNetwork::Socket::messages;
