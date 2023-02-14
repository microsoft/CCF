// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"

#include <atomic>
#include <chrono>

namespace ccf
{
  namespace enclavetime
  {
    extern std::atomic<long long>* host_time_us;
    extern std::atomic<std::chrono::microseconds> last_value;
  }

  static std::chrono::microseconds get_enclave_time()
  {
    // Update cached value if possible, but never move backwards
    if (enclavetime::host_time_us != nullptr)
    {
      const auto current_time = enclavetime::host_time_us->load();
      if (current_time >= enclavetime::last_value.load().count())
      {
        enclavetime::last_value = std::chrono::microseconds(current_time);
      }
      else
      {
        LOG_FAIL_FMT(
          "Host attempting to move enclave time backwards! Last value was {}, "
          "now {}",
          enclavetime::last_value.load().count(),
          current_time);
      }
    }

    return enclavetime::last_value;
  }
}