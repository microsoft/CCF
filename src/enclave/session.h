// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/odata_error.h"
#include "http/http_builder.h"

#include <sys/socket.h>
#include <vector>

namespace ccf
{
  class Session : public std::enable_shared_from_this<Session>
  {
  public:
    virtual ~Session() = default;

    // TODO: Spans?
    virtual void handle_incoming_data(const uint8_t* data, size_t size) = 0;
    virtual void send_data(std::span<const uint8_t> data) = 0;
  };
}
