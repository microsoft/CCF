// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

/*
 * Definitions of various types.
 */
#include <limits.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

typedef long long Time;

#include "cycle_counter.h"

extern long long clock_mhz;
// Clock frequency in MHz

extern void init_clock_mhz();
// Effects: Initialize "clock_mhz".

extern Time current_time();

extern Time zero_time();

extern long long diff_time(Time t1, Time t2);

extern bool less_than_time(Time t1, Time t2);
