// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include <sys/time.h>
#include <time.h>

int gettimeofday(struct timeval* tv, void* tz)
{
  return 0;
}

struct tm* localtime_r(const time_t* timep, struct tm* result)
{
  return 0;
}