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
    auto last = enclavetime::last_value.load();

    // Update cached value if possible, but never move backwards
    if (enclavetime::host_time_us != nullptr)
    {
      const auto current_time = enclavetime::host_time_us->load();
      if (current_time >= last.count())
      {
        // If this fails, it simply means another thread has fetched and updated
        // the in-enclave last_value independently. Both are happy that their
        // values do not decrease time, so either may succeed.
        enclavetime::last_value.compare_exchange_weak(
          last, std::chrono::microseconds(current_time));
      }
      else
      {
        LOG_FAIL_FMT(
          "Host attempting to move enclave time backwards! Last value was {}, "
          "now {}",
          last.count(),
          current_time);
      }
    }

    return last;
  }
}