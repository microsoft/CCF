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

  static constexpr ThreadID MAIN_THREAD_ID = 0;

  uint16_t get_current_thread_id();
  void reset_thread_id_generator();
}