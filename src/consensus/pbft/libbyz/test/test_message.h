// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

struct test_req
{
  char option;

  uint64_t* get_counter_array()
  {
    return (uint64_t*)((uintptr_t)this + sizeof(test_req));
  }

  size_t get_array_size(size_t total_size)
  {
    if (total_size < sizeof(test_req))
    {
      return 0;
    }
    return (total_size - sizeof(test_req)) / sizeof(uint64_t);
  }
};
