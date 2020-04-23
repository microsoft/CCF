// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "timer.h"

#include <atomic>

namespace asynchost
{
  class TimeUpdaterImpl
  {
    std::atomic<uint64_t> rdtsc_value;

  public:
    TimeUpdaterImpl() {}

    std::atomic<uint64_t>* get_value()
    {
      return &rdtsc_value;
    }

    void on_timer()
    {
      rdtsc_value = __rdtsc();
    }
  };

  using TimeUpdater = proxy_ptr<Timer<TimeUpdaterImpl>>;
}
