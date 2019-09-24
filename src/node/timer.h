// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/spinlock.h"

#include <chrono>
#include <functional>
#include <list>

namespace ccf
{
  using TimerCallback = std::function<void()>;

  // TODO: Should this move to inside Timers?

  // TODO: Support expiry of timers
  class Timer
  {
  private:
    SpinLock lock;
    std::chrono::milliseconds period;
    std::chrono::milliseconds tick_;
    TimerCallback cb;

  public:
    Timer(std::chrono::milliseconds period_, TimerCallback cb_) :
      period(period_),
      cb(cb_)
    {
      // TODO: Call callback straight away?
    }

    void tick(std::chrono::milliseconds elapsed)
    {
      std::lock_guard<SpinLock> guard(lock);

      tick_ += elapsed;
      if (tick_ >= period)
      {
        cb();
        using namespace std::chrono_literals;
        tick_ = 0ms;
      }
    }
  };

  class Timers
  {
  private:
    SpinLock lock;

    // TODO: The type of this should probably change
    // std::unordered_map<TimerId, Timer> timers;
    // using TimerList = std::list<Timer>;
    std::list<Timer> timers;

  public:
    Timers() {}

    void tick(std::chrono::milliseconds elapsed)
    {
      std::lock_guard<SpinLock> guard(lock);

      for (auto& t : timers)
        t.tick(elapsed);
    }

    const Timer& new_timer(std::chrono::milliseconds period, TimerCallback cb)
    {
      timers.emplace_back(Timer(period, cb));
      return timers.back();
    }
  };
}