// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"

#include <chrono>
#include <fmt/format.h>
#include <string>

namespace asynchost
{
  struct TimeBoundLogger
  {
    using TClock = std::chrono::steady_clock;
    static std::string human_time(const TClock::duration& d)
    {
      const auto ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(d).count();
      if (ns < 1000)
        return fmt::format("{}ns", ns);

      const auto us = ns / 1000.0f;
      if (us < 1000)
        return fmt::format("{:>7.03f}us", us);

      const auto ms = us / 1000.0f;
      if (ms < 1000)
        return fmt::format("{:>7.03f}ms", ms);

      const auto s = ms / 1000.0f;
      return fmt::format("{:>7.03f}s", s);
    }

    static std::chrono::nanoseconds default_max_time;

    std::string message;
    TClock::duration max_time;
    TClock::time_point start_time;

    TimeBoundLogger(const std::string& m) : TimeBoundLogger(m, default_max_time)
    {}

    template <typename Rep, typename Period>
    TimeBoundLogger(
      const std::string& m, const std::chrono::duration<Rep, Period>& mt) :
      message(m),
      max_time(std::chrono::duration_cast<TClock::duration>(mt)),
      start_time(TClock::now())
    {}

    ~TimeBoundLogger()
    {
      const auto end_time = TClock::now();
      const auto elapsed = end_time - start_time;
      if (elapsed > max_time)
      {
        LOG_FAIL_FMT(
          "Operation took too long ({}): {}", human_time(elapsed), message);
      }
    }
  };
}