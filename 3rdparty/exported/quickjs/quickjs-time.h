#pragma once

int qjs_gettimeofday(struct timeval* tv, void* tz)
{
  return 0;
}

struct tm* qjs_localtime_r(const time_t* timep, struct tm* result)
{
  return 0;
}

#define gettimeofday qjs_gettimeofday
#define localtime_r qjs_localtime_r