// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <atomic>
#include <fmt/format.h>
#include <fmt/ostream.h>
#include <fmt/std.h>
#include <limits>
#include <map>
#include <thread>

namespace ccf::threading
{
  // Assign monotonic thread IDs for display + storage
  using ThreadID = uint16_t;
  static constexpr ThreadID invalid_thread_id =
    std::numeric_limits<ThreadID>::max();

  static constexpr ThreadID MAIN_THREAD_ID = 0;

  namespace detail
  {
    // These local statics keep thread ID state header-only, so users of logger
    // do not need to link libccf for a separate implementation object.
    // Resetting the generator only affects threads that initialise their
    // thread-local ID after the reset; callers can use set_current_thread_id()
    // for the current thread.
    inline std::atomic<ThreadID>& next_thread_id()
    {
      static std::atomic<ThreadID> next = MAIN_THREAD_ID;
      return next;
    }

    inline ThreadID& current_thread_id()
    {
      thread_local ThreadID current = next_thread_id().fetch_add(1);
      return current;
    }
  }

  inline uint16_t get_current_thread_id()
  {
    return detail::current_thread_id();
  }

  inline void set_current_thread_id(ThreadID to)
  {
    detail::current_thread_id() = to;
  }

  inline void reset_thread_id_generator(ThreadID to = MAIN_THREAD_ID)
  {
    detail::next_thread_id().store(to);
  }
}
