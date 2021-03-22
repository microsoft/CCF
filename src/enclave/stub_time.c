#include <time.h>
#include <sys/time.h>

int gettimeofday(struct timeval *tv, void *tz)
{
    return 0;
}

struct tm *localtime_r(const time_t *timep, struct tm *result)
{
    return 0;
}