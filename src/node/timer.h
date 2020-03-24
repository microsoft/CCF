// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "ds/spin_lock.h"

#include <chrono>
#include <functional>
#include <set>

namespace ccf
{
  using TimerCallback = std::function<bool()>;

  class TickingTimer
  {
  public:
    virtual ~TickingTimer() {}
    virtual void tick(std::chrono::milliseconds elapsed_) = 0;
  };

  class Timer
  {
  public:
    virtual ~Timer() {}
    virtual void start() = 0;
  };

  /**
   * A timer class to trigger actions periodically.
   *
   * A shared_ptr to a new Timer is returned by Timers::new_timer(period, cb).
   * The timer is only active when it is started (start()) and marked as expired
   * when the callback is triggered. If the callback returns true, the timer
   * continues ticking. Otherwise, the timer expires and will tick again only
   * when it is explicitly re-started (start()).
   *
   * Note that if the timer's period is smaller than the period at which it is
   * ticked, the callback is only called once per period.
   *
   **/

  class TimerImpl : public TickingTimer, public Timer
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
    std::chrono::milliseconds elapsed;
    TimerCallback cb;
    TimerState state;

  public:
    TimerImpl(std::chrono::milliseconds period_, TimerCallback cb_) :
      period(period_),
      elapsed(0),
      cb(cb_),
      state(TimerState::STOPPED)
    {}

    void start()
    {
      std::lock_guard<SpinLock> guard(lock);
      state = TimerState::STARTED;
    }

    void tick(std::chrono::milliseconds elapsed_)
    {
      std::lock_guard<SpinLock> guard(lock);

      if (state != TimerState::STARTED)
        return;

      elapsed += elapsed_;
      if (elapsed >= period)
      {
        state = TimerState::EXPIRED;
        if (cb())
          state = TimerState::STARTED;

        using namespace std::chrono_literals;
        elapsed = 0ms;
      }
    }
  };

  class Timers
  {
  private:
    SpinLock lock;
    std::set<
      std::weak_ptr<TickingTimer>,
      std::owner_less<std::weak_ptr<TickingTimer>>>
      timers;

  public:
    Timers() {}

    void tick(std::chrono::milliseconds elapsed)
    {
      std::lock_guard<SpinLock> guard(lock);

      auto it = timers.begin();
      while (it != timers.end())
      {
        auto t = it->lock();
        if (t)
        {
          t->tick(elapsed);
          it++;
        }
        else
        {
          it = timers.erase(it);
        }
      }
    }

    std::shared_ptr<Timer> new_timer(
      std::chrono::milliseconds period, TimerCallback cb_)
    {
      std::lock_guard<SpinLock> guard(lock);

      auto timer = std::make_shared<TimerImpl>(period, cb_);
      timers.emplace(timer);

      return std::static_pointer_cast<Timer>(timer);
    }
  };
}