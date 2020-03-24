// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "consensus/pbft/libbyz/cycle_counter.h"
#include "consensus/pbft/libbyz/itimer.h"
#include "consensus/pbft/libbyz/message.h"
#include "consensus/pbft/libbyz/statistics.h"
#include "consensus/pbft/libbyz/time_types.h"
#include "consensus/pbft/libbyz/types.h"
#include "node/node_to_node.h"
#include "pbft_types.h"

#include <signal.h>

ITimer::ITimer(int t, handler_cb h_, void* owner_)
{
  state = stopped;

  period = t * clock_mhz;

  h = h_;
  owner = owner_;
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

  deadline = _relative_current_time;
  deadline += period;

  if (deadline < min_deadline)
  {
    min_deadline = deadline;
  }
}

void ITimer::adjust(int t)
{
  period = t;
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

void ITimer::handle_timeouts(std::chrono::milliseconds elapsed)
{
  if (Byz_execution_pending())
  {
    return;
  }

  _relative_current_time += elapsed.count();
  _handle_timeouts(_relative_current_time);
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
  return _relative_current_time;
}

Time ITimer::length_100_ms()
{
  return 100;
}

Time ITimer::length_10_ms()
{
  return ITimer::length_100_ms() / 10;
}

void init_clock_mhz() {}

Time zero_time()
{
  return 0;
}

long long diff_time(Time t1, Time t2)
{
  return (t1 - t2) / clock_mhz;
}

bool less_than_time(Time t1, Time t2)
{
  return t1 < t2;
}

Statistics::Statistics() : rec_stats(20) {}

void Statistics::zero_stats() {}

void Statistics::print_stats() {}

Recovery_stats::Recovery_stats() {}

void Statistics::init_rec_stats() {}

void Statistics::end_rec_stats() {}

void Recovery_stats::zero_stats() {}

void Recovery_stats::print_stats() {}
