// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ccf
{
  struct FluentdConfig
  {
    enum class Delivery : uint8_t
    {
      BUFFERED_BEST_EFFORT,
      UNBUFFERED_NON_BLOCKING
    };

    // Hostname or IP address and decimal TCP port of an in_forward listener.
    std::string host;
    std::string port;
    size_t queue_capacity = 4096;
    Delivery delivery = Delivery::BUFFERED_BEST_EFFORT;
    std::vector<std::string> tag_prefix_allow_list = {"ccf.log"};

    bool operator==(const FluentdConfig&) const = default;
  };
}
