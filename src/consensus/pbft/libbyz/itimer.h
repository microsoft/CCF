// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "time_types.h"
#include "types.h"

#include <chrono>
#include <vector>

class ITimer
{
  //
  // Interface to a real time interval timer that can be in three
  // states running, stopped and expired. A timer is initially stopped
  // and start changes its state to running. If the timer is not
  // explicitly stopped (by calling stop) before time t elapses, the
  // timer expires, and the handler is called the next time
  // handle_timeouts is called.
  //

public:
  typedef void (*handler_cb)(void* owner);
  ITimer(int t, handler_cb h, void* owner);
  // Effects: Creates a timer that expires after running for time "t"
  // msecs and calls handler "h" passing owner when it expires.

  ~ITimer();
  // Effects: Deletes a timer.

  void start();
  // Effects: If state is stopped, starts the timer. Otherwise, it has
  // no effect.

  void restart();
  // Effects: Like start, but also starts the timer if state is expired.

  void adjust(int t);
  // Effects: Adjusts the timeout period to "t" msecs.

  void stop();
  // Effects: If state is running, stops the timer. Otherwise, it has
  // no effect.

  void restop();
  // Effects: Like stop, but also changes state to stopped if state is expired.

  enum State
  {
    stopped,
    running,
    expired
  };
  State get_state() const;

  static void handle_timeouts();
  static void handle_timeouts(std::chrono::milliseconds elapsed);
  // Effects: Calls handlers for ITimer instances that have expired.

  static Time current_time();
  // Effects: Returns the current time

  static Time length_100_ms();
  static Time length_10_ms();
  // Effects: Returns the length of 10ms,100ms

private:
  State state;
  handler_cb h;
  void* owner;

  Time deadline;
  Time period;

  // Use cycle counter
  static Time min_deadline;
  static void _handle_timeouts(Time current);
  static Time _relative_current_time;

  static std::vector<ITimer*> timers;
};
