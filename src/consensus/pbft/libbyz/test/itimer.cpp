// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "itimer.h"

#include "cycle_counter.h"
#include "types.h"

#include <signal.h>

std::vector<ITimer*> ITimer::timers;
Time ITimer::min_deadline = Long_max;

ITimer::ITimer(int t, handler_cb h, void* owner) :
  state(stopped),
  h(h),
  owner(owner),
  period(t * clock_mhz * 1000)
{
  timers.push_back(this);
}

ITimer::~ITimer()
{
  for (size_t i = 0; i < timers.size(); i++)
  {
    if (timers[i] == this)
    {
      timers[i] = timers.back();
      timers.pop_back();
      break;
    }
  }
}

void ITimer::start()
{
  if (state != stopped)
  {
    return;
  }
  restart();
}

void ITimer::restart()
{
  if (state != stopped && state != expired)
  {
    return;
  }

  state = running;

  deadline = rdtsc();
  deadline += period;

  if (deadline < min_deadline)
  {
    min_deadline = deadline;
  }
}

void ITimer::adjust(int t)
{
  period = t * clock_mhz * 1000;
}

void ITimer::stop()
{
  if (state != running)
  {
    return;
  }

  state = stopped;
}

void ITimer::restop()
{
  state = stopped;
}

ITimer::State ITimer::get_state() const
{
  return state;
}

void ITimer::handle_timeouts()
{
  Time current = rdtsc();
  if (current < min_deadline)
  {
    return;
  }
  _handle_timeouts(current);
}

void ITimer::_handle_timeouts(Time current)
{
  min_deadline = 9223372036854775807LL;

  for (size_t i = 0; i < timers.size(); i++)
  {
    ITimer* timer = timers[i];
    if (timer->state == running)
    {
      if (timer->deadline < current)
      {
        timer->state = expired;
        timer->h(timer->owner);
      }
      else
      {
        if (timer->deadline < min_deadline)
        {
          min_deadline = timer->deadline;
        }
      }
    }
  }
}

Time ITimer::current_time()
{
  return rdtsc();
}

Time ITimer::length_100_ms()
{
  return 100000;
}

Time ITimer::length_10_ms()
{
  return ITimer::length_100_ms() / 10;
}
