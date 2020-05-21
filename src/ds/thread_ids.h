// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <fmt/ostream.h>
#include <map>
#include <thread>

namespace threading
{
  extern std::map<std::thread::id, uint16_t> thread_ids;

  static inline uint16_t get_current_thread_id()
  {
    if (thread_ids.empty())
    {
      return 0;
    }

    const auto tid = std::this_thread::get_id();
    const auto it = thread_ids.find(tid);
    if (it == thread_ids.end())
    {
      throw std::runtime_error(
        fmt::format("Accessed uninitialised thread_ids - ID {} unknown", tid));
    }

    return it->second;
  }
}