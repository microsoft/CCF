// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/threading/thread_ids.h"

namespace ccf::threading
{
  static std::atomic<ThreadID> next_thread_id = MAIN_THREAD_ID;

  static thread_local std::optional<std::string> this_thread_name =
    std::nullopt;

  uint16_t& current_thread_id()
  {
    thread_local ThreadID this_thread_id = next_thread_id.fetch_add(1);
    return this_thread_id;
  }

  uint16_t get_current_thread_id()
  {
    return current_thread_id();
  }

  void set_current_thread_id(ThreadID to)
  {
    current_thread_id() = to;
  }

  void reset_thread_id_generator(ThreadID to)
  {
    next_thread_id.store(to);
  }

  std::string get_current_thread_name()
  {
    if (!this_thread_name.has_value())
    {
      this_thread_name = fmt::format("{}", get_current_thread_id());
    }

    return this_thread_name.value();
  }

  void set_current_thread_name(std::string_view sv)
  {
    this_thread_name = sv;
  }
}