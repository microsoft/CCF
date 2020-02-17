// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "types.h"

class RequestIdGenerator
{
public:
  RequestIdGenerator();
  //
  // Unique identifier generation:
  //
  Request_id next_rid();
  // Effects: Computes a new request identifier. The new request
  // identifier is guaranteed to be larger than any request identifier
  // produced by the node in the past (even accross) reboots (assuming
  // clock as returned by gettimeofday retains value after a crash.)
private:
  std::atomic<Request_id> cur_rid; // state for unique identifier generator.
};
