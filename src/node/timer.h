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
  using TimerCallback = std::function<bool()>;

  /**
   * A timer class to trigger actions periodically.
   *
   * A shared_ptr to a new Timer is returned by Timers::new_timer(period, cb).
   * The timer is only active when it is started (start()) and marked as expired
   * when the callback is triggered. If the callback returns true, the timer
   * continues ticking. Otherwise, the timer expires and will tick again only
   * when it is explicitely re-started (start()).
   *
   **/
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

    void start()
    {
      std::lock_guard<SpinLock> guard(lock);
      state = TimerState::STARTED;
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
        if (cb())
          state = TimerState::STARTED;

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
  };
}