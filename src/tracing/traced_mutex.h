// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/thread_safety.h"

#include <cstdint>
#include <mutex>

namespace ccf::tracing
{
  // The hold of a TracedMutex that the current thread is in, or 0 if none.
  // Trace events record it, so a trace shows which events each critical
  // section emitted.
  inline thread_local uint64_t lock_hold = 0;

  // A mutex that numbers its holds from 1, in the order they are acquired.
  class CCF_CAPABILITY("mutex") TracedMutex
  {
  private:
    std::mutex mutex;
    // Written only while holding mutex
    uint64_t holds = 0;
    uint64_t outer = 0;

  public:
    void lock() CCF_ACQUIRE()
    {
      mutex.lock();
      outer = lock_hold;
      lock_hold = ++holds;
    }

    void unlock() CCF_RELEASE()
    {
      lock_hold = outer;
      mutex.unlock();
    }
  };
}
