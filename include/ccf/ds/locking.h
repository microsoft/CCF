// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/thread_safety.h"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <utility>

namespace ccf::ds
{
  class ConditionVariable;
  class MutexGuard;

  /**
   * Generic locking primitives shared across CCF components.
   */
  class CCF_CAPABILITY("mutex") Mutex
  {
  private:
    friend class ConditionVariable;
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
  };

  class ConditionVariable
  {
  private:
    class NativeLock
    {
    private:
      std::unique_lock<std::mutex> lock;

    public:
      explicit NativeLock(std::mutex& mutex) : lock(mutex, std::adopt_lock) {}

      ~NativeLock()
      {
        lock.release();
      }

      std::unique_lock<std::mutex>& get()
      {
        return lock;
      }
    };

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
      NativeLock lock(guard.mutex.mutex);
      condition_variable.wait(lock.get());
    }

    template <typename Predicate>
    void wait(MutexGuard& guard, Predicate predicate)
    {
      NativeLock lock(guard.mutex.mutex);
      condition_variable.wait(lock.get(), std::move(predicate));
    }

    template <typename Rep, typename Period>
    std::cv_status wait_for(
      MutexGuard& guard,
      const std::chrono::duration<Rep, Period>& relative_time)
    {
      NativeLock lock(guard.mutex.mutex);
      return condition_variable.wait_for(lock.get(), relative_time);
    }

    template <typename Rep, typename Period, typename Predicate>
    bool wait_for(
      MutexGuard& guard,
      const std::chrono::duration<Rep, Period>& relative_time,
      Predicate predicate)
    {
      NativeLock lock(guard.mutex.mutex);
      return condition_variable.wait_for(
        lock.get(), relative_time, std::move(predicate));
    }

    template <typename Clock, typename Duration>
    std::cv_status wait_until(
      MutexGuard& guard,
      const std::chrono::time_point<Clock, Duration>& timeout_time)
    {
      NativeLock lock(guard.mutex.mutex);
      return condition_variable.wait_until(lock.get(), timeout_time);
    }

    template <typename Clock, typename Duration, typename Predicate>
    bool wait_until(
      MutexGuard& guard,
      const std::chrono::time_point<Clock, Duration>& timeout_time,
      Predicate predicate)
    {
      NativeLock lock(guard.mutex.mutex);
      return condition_variable.wait_until(
        lock.get(), timeout_time, std::move(predicate));
    }
  };
}
