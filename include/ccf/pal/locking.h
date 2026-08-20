// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/thread_safety.h"

#include <condition_variable>
#include <mutex>

namespace ccf::pal
{
  class MutexGuard;

  /**
   * Virtual enclaves and the host code share the same PAL.
   */
  class CCF_CAPABILITY("mutex") Mutex
  {
  private:
    friend class MutexGuard;
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
    friend class ConditionVariable;
    Mutex& mutex;
    std::unique_lock<std::mutex> lock;

  public:
    explicit MutexGuard(Mutex& mutex_) CCF_ACQUIRE(mutex_) : mutex(mutex_)
    {
      mutex.lock();
      lock = std::unique_lock<std::mutex>(mutex.mutex, std::adopt_lock);
    }

    ~MutexGuard() CCF_RELEASE()
    {
      lock.release();
      mutex.unlock();
    }

    MutexGuard(const MutexGuard&) = delete;
    MutexGuard& operator=(const MutexGuard&) = delete;
  };

  class ConditionVariable
  {
  private:
    std::condition_variable condition_variable;

  public:
    void notify_one() noexcept
    {
      condition_variable.notify_one();
    }

    void notify_all() noexcept
    {
      condition_variable.notify_all();
    }

    void wait(MutexGuard& guard)
    {
      condition_variable.wait(guard.lock);
    }

    template <typename Rep, typename Period>
    std::cv_status wait_for(
      MutexGuard& guard,
      const std::chrono::duration<Rep, Period>& relative_time)
    {
      return condition_variable.wait_for(guard.lock, relative_time);
    }

    template <typename Clock, typename Duration>
    std::cv_status wait_until(
      MutexGuard& guard,
      const std::chrono::time_point<Clock, Duration>& timeout_time)
    {
      return condition_variable.wait_until(guard.lock, timeout_time);
    }
  };
}
