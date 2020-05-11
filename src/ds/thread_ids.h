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
    return thread_ids[std::this_thread::get_id()];
  }
}