// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <atomic>

namespace enclave
{
  extern std::atomic<uint64_t>* rdtsc_source;
  extern uint64_t last_rdtsc_value;

  static uint64_t get_enclave_time()
  {
    // Update cached value if possible, but never move backwards
    if (rdtsc_source != nullptr)
    {
      const auto current_rdtsc_value = rdtsc_source->load();
      if (current_rdtsc_value > last_rdtsc_value)
      {
        last_rdtsc_value = current_rdtsc_value;
      }
    }

    return last_rdtsc_value;
  }
}