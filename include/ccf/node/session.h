// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <span>

namespace ccf
{
  class Session
  {
  public:
    virtual ~Session() = default;

    virtual void handle_incoming_data(std::span<const uint8_t> data) = 0;
    virtual void send_data(std::vector<uint8_t>&& data) = 0;
    virtual void close_session() = 0;
  };
}