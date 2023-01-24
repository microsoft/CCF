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
  // TODO: Simplify registration. Don't require manual population of thread_ids
  // map, instead just monotonically assign (by compare-and-swap) with
  // next-highest. Move MAIN_THREAD_ID from static constexpr, to statically
  // assigned.
  static constexpr size_t MAIN_THREAD_ID = 0;

  // Assign monotonic thread IDs for display + storage
  using ThreadID = uint16_t;
  static constexpr ThreadID invalid_thread_id =
    std::numeric_limits<ThreadID>::max();

  static inline thread_local ThreadID this_thread_id = invalid_thread_id;
  static std::atomic<ThreadID> next_thread_id;

  static inline uint16_t get_current_thread_id()
  {
    if (this_thread_id == invalid_thread_id)
    {
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