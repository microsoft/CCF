// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <fmt/ostream.h>
#include <fmt/std.h>
#include <limits>
#include <map>
#include <thread>

namespace threading
{
  // Assign monotonic thread IDs for display + storage
  using ThreadID = uint16_t;
  static constexpr ThreadID invalid_thread_id =
    std::numeric_limits<ThreadID>::max();

  static inline thread_local ThreadID this_thread_id = invalid_thread_id;

  static constexpr ThreadID MAIN_THREAD_ID = 0;
  static std::atomic<ThreadID> next_thread_id = MAIN_THREAD_ID;

  static inline uint16_t get_current_thread_id()
  {
    if (this_thread_id == invalid_thread_id)
    {
      // First time this is called (per-thread), grab the next available
      // thread_id
      ThreadID assigned_id = 0;
      while (
        !next_thread_id.compare_exchange_strong(assigned_id, assigned_id + 1))
      {
        // Empty loop body
      }

      this_thread_id = assigned_id;
    }

    return this_thread_id;
  }
}