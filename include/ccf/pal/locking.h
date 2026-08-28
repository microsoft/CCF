// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/thread_safety.h"

#include <condition_variable>
#include <mutex>
#include <source_location>
#include <utility>

namespace ccf::pal
{
  class ConditionVariable;
  class MutexGuard;

#if defined(CCF_TEST_INTERLEAVING_LOCK_TYPE)
  // A test build may define this (before this header is first included,
  // via a -include compiler flag applying to every source file in that
  // build) to replace ccf::pal::Mutex itself, everywhere, with a different,
  // instrumented lock type - see that type's own declaration for what it
  // does instead of real locking. MutexGuard and ConditionVariable below
  // are both written against the name Mutex, so they bind to whichever
  // type this resolves to; the replacement type must therefore expose the
  // same public lock()/try_lock()/unlock() surface, and (for
  // ConditionVariable::wait() and friends to keep compiling) a private
  // member also named `mutex`, friended to ConditionVariable, of type
  // std::mutex.
  using Mutex = CCF_TEST_INTERLEAVING_LOCK_TYPE;
#else
  /**
   * Virtual enclaves and the host code share the same PAL.
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
#endif

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

  // Called (if non-null) whenever a ccf::pal::unique_lock below actually
  // acquires its lock, with a short label describing why - either given
  // explicitly at the call site, or (if not) a source-location-derived
  // default. Null outside of test code that wants to observe this; see
  // src/commit_concurrency/deterministic_scheduler.h's SchedulerThreadContext,
  // the one place that currently sets it, forwarding to
  // DeterministicScheduler::set_action() so a failing scenario's
  // describe() can show real semantic reasons at real lock points, not
  // just its own explicit yield_point() labels. Deliberately not
  // thread_local: the one place that installs it already reads its own
  // thread-local state to decide whether the calling thread has an active
  // scheduler, so this only ever needs a single, one-time global install.
  using LockLabelSink = void (*)(const char* label);
  inline LockLabelSink lock_label_sink = nullptr;

  // A drop-in replacement for std::unique_lock<Mutex> (supporting the same
  // deferred-locking constructor and lock()/try_lock()/unlock() surface
  // used against ccf::pal::Mutex elsewhere in this codebase), with an
  // optional label describing why this lock is being taken - reported to
  // lock_label_sink above every time this actually acquires the lock. With
  // no label given, the label defaults to the call site's source location.
  template <typename LockType>
  class unique_lock
  {
    std::unique_lock<LockType> inner;
    const char* label;
    std::source_location loc;

    void report_if_locked()
    {
      if (inner.owns_lock() && lock_label_sink != nullptr)
      {
        lock_label_sink(label != nullptr ? label : loc.function_name());
      }
    }

  public:
    explicit unique_lock(
      LockType& mtx,
      const char* label_ = nullptr,
      std::source_location loc_ = std::source_location::current()) :
      inner(mtx),
      label(label_),
      loc(loc_)
    {
      report_if_locked();
    }

    unique_lock(
      LockType& mtx,
      std::defer_lock_t defer,
      const char* label_ = nullptr,
      std::source_location loc_ = std::source_location::current()) :
      inner(mtx, defer),
      label(label_),
      loc(loc_)
    {}

    void lock()
    {
      inner.lock();
      report_if_locked();
    }

    bool try_lock()
    {
      const bool locked = inner.try_lock();
      if (locked)
      {
        report_if_locked();
      }
      return locked;
    }

    void unlock()
    {
      inner.unlock();
    }

    bool owns_lock() const
    {
      return inner.owns_lock();
    }

    unique_lock(const unique_lock&) = delete;
    unique_lock& operator=(const unique_lock&) = delete;
  };
}
