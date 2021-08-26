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
    using TClock = std::chrono::system_clock;

    std::atomic<std::chrono::microseconds> time_now;

  public:
    TimeUpdaterImpl()
    {
      on_timer();
    }

    std::atomic<std::chrono::microseconds>* get_value()
    {
      return &time_now;
    }

    void on_timer()
    {
      time_now = std::chrono::duration_cast<std::chrono::microseconds>(
        TClock::now().time_since_epoch());
    }
  };

  using TimeUpdater = proxy_ptr<Timer<TimeUpdaterImpl>>;
}
