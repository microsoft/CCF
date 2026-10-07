// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/task_system.h"
#include "timer.h"

#include <chrono>
#include <optional>

namespace asynchost
{
  class TaskTickerImpl
  {
    using Clock = std::chrono::steady_clock;
    std::optional<Clock::time_point> last_tick = std::nullopt;

  public:
    void on_timer()
    {
      const auto now = Clock::now();
      if (last_tick.has_value())
      {
        const auto elapsed =
          std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_tick.value());
        if (elapsed.count() > 0)
        {
          ccf::tasks::tick(elapsed);
          last_tick.value() += elapsed;
        }
      }
      else
      {
        last_tick = now;
      }
    }
  };

  using TaskTicker = ccf::uv::proxy_ptr<Timer<TaskTickerImpl>>;
}
