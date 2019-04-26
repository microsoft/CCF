// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <vector>

namespace enclave
{
  class Endpoint
  {
  public:
    virtual ~Endpoint() {}

    virtual void recv(const uint8_t* data, size_t size) = 0;
    virtual void send(const std::vector<uint8_t>& data) = 0;
    virtual void close() = 0;

    virtual bool handle_data(const std::vector<uint8_t>& data) = 0;
  };
}
