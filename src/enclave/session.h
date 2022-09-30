// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <sys/socket.h>
#include <vector>

namespace ccf
{
  class Session : public std::enable_shared_from_this<Session>
  {
  public:
    virtual ~Session() {}

    virtual void handle_incoming_data(const uint8_t* data, size_t size) = 0;
    virtual void send(std::vector<uint8_t>&& data, sockaddr addr = {}) = 0;
    virtual void send(const uint8_t* data, size_t size)
    {
      send({data, data + size}, sockaddr{});
    }
  };
}
