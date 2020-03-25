// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

static inline long long rdtsc(void)
{
  union
  {
    struct
    {
      unsigned int l; /* least significant word */
      unsigned int h; /* most significant word */
    } w32;
    unsigned long long w64;
  } v;

  __asm __volatile(".byte 0xf; .byte 0x31     # RDTSC instruction"
                   : "=a"(v.w32.l), "=d"(v.w32.h)
                   :);
  return v.w64;
}

class Cycle_counter
{
public:
  Cycle_counter();
  // Effects: Create stopped counter with 0 cycles.

  void reset();
  // Effects: Reset counter to 0 and stop it.

  void start();
  // Effects: Start counter.

  void stop();
  // Effects: Stop counter and accumulate cycles since last started.

  long long elapsed();
  // Effects: Return cycles for which counter has run until now since
  // it was created or last reset.

  long long max_increment();
  // Effects: Return maximum number of cycles added to "accummulated" by
  // "stop()"

private:
  long long c0, c1;
  long long accumulated;
  long long max_incr;
  bool running;

  // This variable should be set to the "average" value of c.elapsed()
  // after:
  // Cycle_counter c; c.start(); c.stop();
  //
  // The purpose is to avoid counting in the measurement overhead.
  static const long long calibration = 37;
};

inline void Cycle_counter::reset()
{
  accumulated = 0;
  running = false;
  max_incr = 0;
}

inline Cycle_counter::Cycle_counter()
{
  reset();
}

inline void Cycle_counter::start()
{
  if (!running)
  {
    running = true;
    c0 = rdtsc();
  }
}

inline void Cycle_counter::stop()
{
  if (running)
  {
    running = false;
    c1 = rdtsc();
    long long incr = c1 - c0 - calibration;
    if (incr > max_incr)
      max_incr = incr;
    accumulated += incr;
  }
}

inline long long Cycle_counter::elapsed()
{
  if (running)
  {
    c1 = rdtsc();
    return (accumulated + c1 - c0 - calibration);
  }
  else
  {
    return accumulated;
  }
}

inline long long Cycle_counter::max_increment()
{
  return max_incr;
}
