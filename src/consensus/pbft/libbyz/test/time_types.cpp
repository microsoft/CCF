// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "time_types.h"

long long clock_mhz = 0;

void init_clock_mhz()
{
  struct timeval t0, t1;

  long long c0 = rdtsc();
  gettimeofday(&t0, 0);
  sleep(1);
  long long c1 = rdtsc();
  gettimeofday(&t1, 0);

  clock_mhz =
    (c1 - c0) / ((t1.tv_sec - t0.tv_sec) * 1000000 + t1.tv_usec - t0.tv_usec);
}

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
