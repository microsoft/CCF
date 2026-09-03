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

  // Satisfied by a lock type whose lock()/try_lock()/unlock() calls can
  // each be given a short label describing why - the only current
  // example is ccf::kv::test::SchedulerMutex, which reports each label
  // straight to whichever scheduler is exploring interleavings on the
  // calling thread, as an Acquired or Released event tied precisely to
  // that specific call - see its lock()/unlock() for details.
  // ccf::pal::Mutex itself does not satisfy this (real locking has no use
  // for a label), so unique_lock below falls back to plain, unlabelled
  // lock()/try_lock()/unlock() calls against it.
  template <typename LockType>
  concept LabelledLockable = requires(LockType& mtx, const char* label) {
    mtx.lock(label);
    mtx.try_lock(label);
    mtx.unlock(label);
  };

  // A drop-in replacement for std::unique_lock<Mutex> (supporting the same
  // deferred-locking constructor and lock()/try_lock()/unlock() surface
  // used against ccf::pal::Mutex elsewhere in this codebase), with an
  // optional label describing why this lock is being taken - passed
  // directly into the underlying LockType's own lock()/try_lock()/unlock()
  // call for LockTypes that accept one (see LabelledLockable above); a
  // plain, unlabelled call otherwise. With no label given, it defaults to
  // the call site's source location.
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
      if constexpr (LabelledLockable<LockType>)
      {
        mtx->lock(effective_label());
      }
      else
      {
        mtx->lock();
      }
      owned = true;
    }

    bool try_lock() CCF_TRY_ACQUIRE(true)
    {
      bool locked;
      if constexpr (LabelledLockable<LockType>)
      {
        locked = mtx->try_lock(effective_label());
      }
      else
      {
        locked = mtx->try_lock();
      }
      owned = locked;
      return locked;
    }

    void unlock() CCF_RELEASE()
    {
      if constexpr (LabelledLockable<LockType>)
      {
        mtx->unlock(effective_label());
      }
      else
      {
        mtx->unlock();
      }
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
