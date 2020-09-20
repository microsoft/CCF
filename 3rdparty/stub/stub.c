#include <stdlib.h>
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

/* oe_memset_s is an internal OE function, so not in any of the installed header files. */
int oe_memset_s(void* dst, size_t dst_size, int value, size_t num_bytes);

void explicit_bzero(void *s, size_t n)
{
  oe_memset_s(s, n, 0, n);
}