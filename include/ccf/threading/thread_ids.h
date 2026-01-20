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
#include <atomic>

namespace ccf::threading
{
  // Assign monotonic thread IDs for display + storage
  using ThreadID = uint16_t;
  static constexpr ThreadID invalid_thread_id =
    std::numeric_limits<ThreadID>::max();

  static constexpr ThreadID MAIN_THREAD_ID = 0;

  static inline std::atomic<ThreadID>& get_next_thread_id()
  {
    static std::atomic<ThreadID> next_thread_id = MAIN_THREAD_ID;
    return next_thread_id;
  }

  static inline uint16_t& current_thread_id()
  {
    thread_local ThreadID this_thread_id = get_next_thread_id().fetch_add(1);
    return this_thread_id;
  }

  static inline uint16_t get_current_thread_id()
  {
    return current_thread_id();
  }

  static inline void set_current_thread_id(ThreadID to)
  {
    current_thread_id() = to;
  }

  static void reset_thread_id_generator(ThreadID to = MAIN_THREAD_ID)
  {
    get_next_thread_id().store(to);
  }
}