// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <chrono>

namespace ccf::ds
{
  // TODO: Docs
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
