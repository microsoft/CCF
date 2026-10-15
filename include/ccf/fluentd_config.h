// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstddef>
#include <string>

namespace ccf
{
  struct FluentdConfig
  {
    // Hostname or IP address and decimal TCP port of an in_forward listener.
    std::string host;
    std::string port;
    size_t queue_capacity = 4096;

    bool operator==(const FluentdConfig&) const = default;
  };
}
