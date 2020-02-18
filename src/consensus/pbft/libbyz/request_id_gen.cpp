// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "request_id_gen.h"

#include "pbft_assert.h"

#include <sys/time.h>

RequestIdGenerator::RequestIdGenerator() : cur_rid(0) {}

Request_id RequestIdGenerator::next_rid()
{
  return ++cur_rid;
}