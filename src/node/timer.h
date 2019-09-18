// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/spinlock.h"

#include <chrono>
#include <functional>
#include <unordered_map>

namespace ccf
{
  using TimerId = uint64_t;

  // TODO: Should this move to inside Timers?

  // TODO: Support expiry of timers
  template <typename T>
  class Timer
  {
    using TimerCallback = std::function<T>;

  private:
    SpinLock lock;
    std::chrono::milliseconds period;
    std::chrono::milliseconds tick;
    TimerCallback cb;

  public:
    Timer(std::chrono::milliseconds period_, TimerCallback cb_) :
      period(period_),
      cb(cb_)
    {}

    void tick(std::chrono::milliseconds elapsed)
    {
      std::lock_guard<SpinLock> guard(lock);

      tick += elapsed;
      if (tick >= period)
      {
        cb();
        using namespace std::chrono_literals;
        tick = 0ms;
      }
    }
  };

  template <typename T>
  class Timers
  {
  private:
    SpinLock lock;

    // TODO: The type of this should probably change
    std::unordered_map<TimerId, Timer<T>> timers;

  public:
    Timers() {}

    void tick(std::chrono::milliseconds elapsed)
    {
      std::lock_guard<SpinLock> guard(lock);

      for (auto& t : timers)
        t.second.tick(elapsed);
    }
  };
}