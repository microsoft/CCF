// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "time_types.h"

long long clock_mhz = 0;

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
