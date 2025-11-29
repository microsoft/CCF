// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/internal_logger.h"

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
      const auto us =
        std::chrono::duration_cast<std::chrono::microseconds>(d).count();
      if (us < 1000)
      {
        return fmt::format("{:>7.03f}us", static_cast<float>(us));
      }

      const auto ms = us / 1000.0f;
      if (ms < 1000)
      {
        return fmt::format("{:>7.03f}ms", ms);
      }

      const auto s = ms / 1000.0f;
      return fmt::format("{:>7.03f}s", s);
    }

    static std::chrono::microseconds default_max_time;

    std::string message;
    TClock::duration max_time;
    TClock::time_point start_time;

    TimeBoundLogger(const std::string& m) : TimeBoundLogger(m, default_max_time)
    {}

    template <typename Rep, typename Period>
    TimeBoundLogger(
      std::string m, const std::chrono::duration<Rep, Period>& mt) :
      message(std::move(m)),
      max_time(std::chrono::duration_cast<TClock::duration>(mt)),
      start_time(TClock::now())
    {}

    ~TimeBoundLogger()
    {
      const auto end_time = TClock::now();
      const auto elapsed = end_time - start_time;
      constexpr auto out_of_distribution_multiplier = 100;
      if (elapsed > max_time * out_of_distribution_multiplier)
      {
        LOG_FAIL_FMT(
          "Operation took too long ({}): {}", human_time(elapsed), message);
      }
      else if (elapsed > max_time)
      {
        LOG_INFO_FMT(
          "Operation took too long ({}): {}", human_time(elapsed), message);
      }
    }
  };
}