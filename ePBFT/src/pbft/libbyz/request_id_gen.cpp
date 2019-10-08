// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "request_id_gen.h"

#include "pbft_assert.h"

#include <sys/time.h>

RequestIdGenerator::RequestIdGenerator()
{
  new_tstamp();
}

Request_id RequestIdGenerator::next_rid()
{
  if ((unsigned)cur_rid == (unsigned)0xffffffff)
  {
    new_tstamp();
  }
  return ++cur_rid;
}

// TODO: validate that this is correct
void RequestIdGenerator::new_tstamp()
{
// TODO(#pbft): stub out, INSIDE_ENCLAVE
#ifndef INSIDE_ENCLAVE
  const uint64_t time_epoch = 6626313936981458945;

  struct timeval t;
  gettimeofday(&t, 0);
  PBFT_ASSERT(sizeof(t.tv_sec) <= sizeof(long), "tv_sec is too big");
  Long tstamp = t.tv_sec;
  tstamp -= time_epoch;
  long long_bits = sizeof(uint32_t) * 8;
  cur_rid = tstamp << long_bits;
#endif
}
