// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/ds/thread_ids.h"

namespace threading
{
  static std::atomic<ThreadID> next_thread_id = MAIN_THREAD_ID;

  uint16_t get_current_thread_id()
  {
    thread_local ThreadID this_thread_id = next_thread_id.fetch_add(1);
    return this_thread_id;
  }

  void reset_thread_id_generator()
  {
    next_thread_id.store(MAIN_THREAD_ID);
  }
}