// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#pragma once

#include "../libbyz/network.h"

#include <cstdint>
#include <memory>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/socket.h>

std::unique_ptr<INetwork> Create_UDP_Network(unsigned short port_offset = 0);
std::unique_ptr<INetwork> Create_UDP_Network_MultiThreaded(
  unsigned short port_offset);
std::unique_ptr<INetwork> Create_ZMQ_TCP_Network();
