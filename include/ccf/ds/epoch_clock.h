// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <chrono>

namespace ccf::ds
{
  // A custom clock type for handling certificate validity periods, which are
  // defined in terms of seconds since the epoch. This avoids issues with
  // system_clock::time_point being unable to represent times after 2262-04-11
  // 23:47:17 UTC (due to tracking nanosecond precision).
  struct EpochClock
  {
    using duration = std::chrono::seconds;
    using rep = duration::rep;
    using period = duration::period;
    using time_point = std::chrono::time_point<EpochClock>;
    static constexpr bool is_steady = false;

    static time_point now() noexcept
    {
      return time_point(duration(std::time(nullptr)));
    }

    static std::time_t to_time_t(const time_point& t) noexcept
    {
      return std::time_t(t.time_since_epoch().count());
    }

    static time_point from_time_t(std::time_t t) noexcept
    {
      return time_point(duration(t));
    }
  };
}
