// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "timer.h"

#include <atomic>
#include <chrono>

namespace asynchost
{
  class TimeUpdaterImpl
  {
    std::atomic<long long> time_now_us;

  public:
    TimeUpdaterImpl()
    {
      on_timer();
    }

    std::atomic<long long>* get_value()
    {
      return &time_now_us;
    }

    void on_timer()
    {
      using TClock = std::chrono::system_clock;
      time_now_us = std::chrono::duration_cast<std::chrono::microseconds>(
                      TClock::now().time_since_epoch())
                      .count();
    }
  };

  using TimeUpdater = proxy_ptr<Timer<TimeUpdaterImpl>>;
}
