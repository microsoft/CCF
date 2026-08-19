// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/thread_safety.h"

#include <mutex>

namespace ccf::pal
{
  /**
   * Virtual enclaves and the host code share the same PAL.
   */
  class CCF_CAPABILITY("mutex") Mutex
  {
  private:
    std::mutex mutex;

  public:
    using native_handle_type = std::mutex::native_handle_type;

    Mutex() = default;
    Mutex(const Mutex&) = delete;
    Mutex& operator=(const Mutex&) = delete;

    void lock() CCF_ACQUIRE()
    {
      mutex.lock();
    }

    bool try_lock() CCF_TRY_ACQUIRE(true)
    {
      return mutex.try_lock();
    }

    void unlock() CCF_RELEASE()
    {
      mutex.unlock();
    }

    native_handle_type native_handle()
    {
      return mutex.native_handle();
    }
  };

  class CCF_SCOPED_CAPABILITY MutexGuard
  {
  private:
    Mutex& mutex;

  public:
    explicit MutexGuard(Mutex& mutex_) CCF_ACQUIRE(mutex_) : mutex(mutex_)
    {
      mutex.lock();
    }

    ~MutexGuard() CCF_RELEASE()
    {
      mutex.unlock();
    }

    MutexGuard(const MutexGuard&) = delete;
    MutexGuard& operator=(const MutexGuard&) = delete;

    void lock() CCF_ACQUIRE()
    {
      mutex.lock();
    }

    void unlock() CCF_RELEASE()
    {
      mutex.unlock();
    }
  };
}
