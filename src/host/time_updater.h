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
    using TClock = std::chrono::steady_clock;
    TClock::time_point creation_time;

    std::atomic<std::chrono::microseconds> us_since_creation;

  public:
    TimeUpdaterImpl() : creation_time(TClock::now()) {}

    std::atomic<std::chrono::microseconds>* get_value()
    {
      return &us_since_creation;
    }

    void on_timer()
    {
      const auto now = TClock::now();
      us_since_creation = std::chrono::duration_cast<std::chrono::microseconds>(
        now - creation_time);
    }
  };

  using TimeUpdater = proxy_ptr<Timer<TimeUpdaterImpl>>;
}
