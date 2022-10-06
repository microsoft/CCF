#pragma once

int qjs_gettimeofday(struct timeval* tv, void* tz)
{
  if (tv != NULL)
  {
    memset(tv, 0, sizeof(struct timeval));
  }
  return 0;
}

struct tm* qjs_localtime_r(const time_t* timep, struct tm* result)
{
  if (result != NULL)
  {
    memset(result, 0, sizeof(struct tm));
  }
  return 0;
}

#define gettimeofday qjs_gettimeofday
#define localtime_r qjs_localtime_r