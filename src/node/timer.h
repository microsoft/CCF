// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "ds/spinlock.h"

#include <chrono>
#include <functional>
#include <list>

namespace ccf
{
  using TimerCallback = std::function<void()>;

  class Timer
  {
  private:
    enum TimerState
    {
      STOPPED = 0,
      STARTED,
      EXPIRED
    };

    SpinLock lock;
    std::chrono::milliseconds period;
    std::chrono::milliseconds tick_;
    TimerCallback cb;
    TimerState state;

  public:
    Timer(std::chrono::milliseconds period_, TimerCallback cb_) :
      period(period_),
      tick_(0),
      cb(cb_),
      state(TimerState::STOPPED)
    {}

    ~Timer()
    {
      LOG_FAIL_FMT("Timer destroyed");
    }

    void start()
    {
      std::lock_guard<SpinLock> guard(lock);
      state = TimerState::STARTED;
    }

    void restart()
    {
      start();
    }

    void stop()
    {
      std::lock_guard<SpinLock> guard(lock);
      state = TimerState::STOPPED;
    }

    void tick(std::chrono::milliseconds elapsed)
    {
      std::lock_guard<SpinLock> guard(lock);

      if (state != TimerState::STARTED)
        return;

      tick_ += elapsed;
      if (tick_ >= period)
      {
        state = TimerState::EXPIRED;
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

    std::list<std::shared_ptr<Timer>> timers;

  public:
    Timers() {}

    void tick(std::chrono::milliseconds elapsed)
    {
      std::lock_guard<SpinLock> guard(lock);

      for (auto& t : timers)
        t->tick(elapsed);
    }

    std::shared_ptr<Timer> new_timer(
      std::chrono::milliseconds period, TimerCallback cb_)
    {
      std::lock_guard<SpinLock> guard(lock);

      timers.emplace_back(std::make_shared<Timer>(period, cb_));
      return timers.back();
    }

    void remove_timer(std::shared_ptr<Timer>& timer)
    {
      std::lock_guard<SpinLock> guard(lock);
      timers.remove(timer);
      // for (auto& t: timers)
      // {
      //   if (t == timer)
      //     timers.erase(t);
      // }
    }
  };
}