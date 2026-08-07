// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <vector>

namespace ccf
{
  class Session
  {
  public:
    virtual ~Session() = default;

    // Inbound bytes for this session. Ownership is transferred, so that the
    // buffer the transport has already built is moved through the session
    // rather than copied again.
    virtual void handle_incoming_data(std::vector<uint8_t>&& data) = 0;
    virtual void send_data(std::vector<uint8_t>&& data) = 0;
    virtual void close_session() = 0;
  };
}