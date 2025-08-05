// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/threading/thread_ids.h"

namespace ccf::threading
{
  static std::atomic<ThreadID> next_thread_id = MAIN_THREAD_ID;

  uint16_t get_current_thread_id()
  {
    thread_local ThreadID this_thread_id = next_thread_id.fetch_add(1);
    return this_thread_id;
  }

  void reset_thread_id_generator(ThreadID to)
  {
    next_thread_id.store(to);
  }
}