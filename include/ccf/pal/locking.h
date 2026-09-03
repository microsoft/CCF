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

  namespace detail
  {
    // Set immediately before Mutex's own lock()/try_lock()/unlock() make
    // their real call, and consumed immediately by whatever runs next on
    // this thread - not read by anything in this header itself. This
    // lets a genuinely real, immediately-following OS-level lock/unlock
    // call (which a bare mutex address alone cannot carry a label
    // through) recover one anyway - see
    // src/commit_concurrency/scheduled/pthread_mutex_wrap.cpp, which
    // intercepts real pthread_mutex_lock/unlock/trylock calls to
    // deterministically explore interleavings, and uses `pending` to
    // tell a genuine ccf::pal::Mutex call apart from every other,
    // unrelated lock in the process (allocator, iostream, etc.) without
    // needing to track any mutex's address at all.
    inline thread_local bool pending = false;
    inline thread_local const char* pending_label = nullptr;
  }

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

    void lock(const char* label = nullptr) CCF_ACQUIRE()
    {
      detail::pending = true;
      detail::pending_label = label;
      mutex.lock();
    }

    bool try_lock(const char* label = nullptr) CCF_TRY_ACQUIRE(true)
    {
      detail::pending = true;
      detail::pending_label = label;
      return mutex.try_lock();
    }

    void unlock(const char* label = nullptr) CCF_RELEASE()
    {
      detail::pending = true;
      detail::pending_label = label;
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

  // A drop-in replacement for std::unique_lock<Mutex> (supporting the same
  // deferred-locking constructor and lock()/try_lock()/unlock() surface
  // used against ccf::pal::Mutex elsewhere in this codebase), with an
  // optional label describing why this lock is being taken - passed
  // directly into Mutex's own lock()/try_lock()/unlock() call. With no
  // label given, it defaults to the call site's source location.
  //
  // Carries its own CCF_SCOPED_CAPABILITY annotations (mirroring
  // MutexGuard above), rather than relying on Clang's built-in,
  // name-based special-casing of std::unique_lock, since this needs to
  // call LockType's own lock()/try_lock()/unlock() directly (to pass a
  // label through) rather than delegating to a real std::unique_lock
  // member. This gives real static verification for the ordinary,
  // unconditional case - a function using this type's lock/unlock like
  // an ordinary scoped guard is checked exactly as if it used
  // std::unique_lock or MutexGuard. The one gap: Clang's built-in
  // std::unique_lock support additionally understands the
  // conditionally-taken pattern (construct with std::defer_lock, only
  // sometimes call .lock()/.try_lock() depending on runtime state) well
  // enough to statically verify it; that specific pattern is not
  // supported for a user-annotated type like this one, and needs
  // CCF_NO_THREAD_SAFETY_ANALYSIS on the specific enclosing function that
  // does it (a handful of call sites in this codebase - see their own
  // comments for why).
  template <typename LockType>
  class CCF_SCOPED_CAPABILITY unique_lock
  {
    LockType* mtx;
    bool owned = false;
    const char* label;
    std::source_location loc;

    const char* effective_label() const
    {
      return label != nullptr ? label : loc.function_name();
    }

  public:
    explicit unique_lock(
      LockType& mtx_,
      const char* label_ = nullptr,
      std::source_location loc_ = std::source_location::current())
      CCF_ACQUIRE(mtx_) :
      mtx(&mtx_),
      label(label_),
      loc(loc_)
    {
      lock();
    }

    unique_lock(
      LockType& mtx_,
      std::defer_lock_t,
      const char* label_ = nullptr,
      std::source_location loc_ = std::source_location::current()) :
      mtx(&mtx_),
      label(label_),
      loc(loc_)
    {}

    ~unique_lock() CCF_RELEASE()
    {
      if (owned)
      {
        unlock();
      }
    }

    void lock() CCF_ACQUIRE()
    {
      mtx->lock(effective_label());
      owned = true;
    }

    bool try_lock() CCF_TRY_ACQUIRE(true)
    {
      const bool locked = mtx->try_lock(effective_label());
      owned = locked;
      return locked;
    }

    void unlock() CCF_RELEASE()
    {
      mtx->unlock(effective_label());
      owned = false;
    }

    bool owns_lock() const
    {
      return owned;
    }

    unique_lock(const unique_lock&) = delete;
    unique_lock& operator=(const unique_lock&) = delete;
  };
}
