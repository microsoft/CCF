// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <map>
#include <thread>

namespace threading
{
  extern std::map<std::thread::id, uint16_t> thread_ids;

  static inline uint16_t get_current_thread_id()
  {
    const auto tid = std::this_thread::get_id();
    const auto it = thread_ids.find(tid);
    if (it == thread_ids.end())
    {
      throw std::runtime_error(
        "Accessed uninitialised thread_ids - ID unknown");
    }

    return it->second;
  }
}