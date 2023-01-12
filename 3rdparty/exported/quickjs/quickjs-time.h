#pragma once

extern int qjs_gettimeofday(struct JSContext* ctx, struct timeval* tv, void* tz);

struct tm* qjs_localtime_r(const time_t* timep, struct tm* result)
{
  if (result != NULL)
  {
    memset(result, 0, sizeof(struct tm));
  }
  return 0;
}

// NB: Capturing JSContext* ctx that is assumed to exist at callsite!
#define gettimeofday(tv, tz) qjs_gettimeofday(ctx, tv, tz)
#define localtime_r qjs_localtime_r