// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <atomic>
#include <chrono>

namespace ccf
{
  extern std::atomic<std::chrono::microseconds>* host_time;
  extern std::chrono::microseconds last_value;

  static std::chrono::microseconds get_enclave_time()
  {
    // Update cached value if possible, but never move backwards
    if (host_time != nullptr)
    {
      const auto current_time = host_time->load();
      if (current_time > last_value)
      {
        last_value = current_time;
      }
    }

    return last_value;
  }
}