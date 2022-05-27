// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <sys/socket.h>
#include <vector>

namespace ccf
{
  class Endpoint : public std::enable_shared_from_this<Endpoint>
  {
  public:
    virtual ~Endpoint() {}

    virtual void recv(const uint8_t* data, size_t size, sockaddr) = 0;
    virtual void send(std::vector<uint8_t>&& data, sockaddr) = 0;
  };
}
