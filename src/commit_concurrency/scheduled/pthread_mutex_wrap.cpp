// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Intercepts every real pthread_mutex_lock()/unlock()/trylock() call in
// this binary (via -Wl,--wrap=..., see CMakeLists.txt), so that a real
// ccf::pal::Mutex - used, unmodified, by production code linked into this
// binary (Store's version_lock, Aft's state->lock, ccf::tasks' job board,
// etc.) - can be driven by a DeterministicScheduler without recompiling
// any of that code against a different Mutex type at all.
//
// ccf::pal::Mutex's own lock()/try_lock()/unlock() (see
// include/ccf/pal/locking.h) set ccf::pal::detail::pending immediately
// before making the real call intercepted here. This is how the
// functions below tell a genuine ccf::pal::Mutex call apart from every
// other, unrelated pthread_mutex_lock/unlock/trylock call anywhere else
// in the binary (allocator internals, iostream, DeterministicScheduler's
// own bookkeeping mutex, etc.), with no need to track any mutex's address
// at all. The flag is consumed (reset to false) the instant it is read,
// so a nested/recursive real lock call - e.g. DeterministicScheduler's
// own internal std::mutex, locked from inside before_lock()/
// after_unlock() themselves - correctly sees it already cleared, and
// falls straight through to a real lock, with no risk of infinite
// recursion.

#include "ccf/pal/locking.h"
#include "commit_concurrency/scheduled/deterministic_scheduler.h"

#include <cstdio>
#include <cstdlib>
#include <pthread.h>

extern "C" int __real_pthread_mutex_lock(pthread_mutex_t* mutex);
extern "C" int __real_pthread_mutex_unlock(pthread_mutex_t* mutex);
extern "C" int __real_pthread_mutex_trylock(pthread_mutex_t* mutex);

namespace
{
  bool consume_pending()
  {
    if (!ccf::pal::detail::pending)
    {
      return false;
    }
    ccf::pal::detail::pending = false;
    return true;
  }
}

extern "C" int __wrap_pthread_mutex_lock(pthread_mutex_t* mutex)
{
  if (!consume_pending())
  {
    return __real_pthread_mutex_lock(mutex);
  }
  auto* scheduler = ccf::kv::test::SchedulerThreadContext::scheduler();
  if (scheduler == nullptr)
  {
    return __real_pthread_mutex_lock(mutex);
  }
  scheduler->before_lock(
    ccf::kv::test::SchedulerThreadContext::actor(),
    mutex,
    ccf::pal::detail::pending_label);
  return 0;
}

extern "C" int __wrap_pthread_mutex_unlock(pthread_mutex_t* mutex)
{
  if (!consume_pending())
  {
    return __real_pthread_mutex_unlock(mutex);
  }
  auto* scheduler = ccf::kv::test::SchedulerThreadContext::scheduler();
  if (scheduler == nullptr)
  {
    return __real_pthread_mutex_unlock(mutex);
  }
  scheduler->after_unlock(
    ccf::kv::test::SchedulerThreadContext::actor(),
    mutex,
    ccf::pal::detail::pending_label);
  return 0;
}

extern "C" int __wrap_pthread_mutex_trylock(pthread_mutex_t* mutex)
{
  if (!consume_pending())
  {
    return __real_pthread_mutex_trylock(mutex);
  }
  auto* scheduler = ccf::kv::test::SchedulerThreadContext::scheduler();
  if (scheduler == nullptr)
  {
    return __real_pthread_mutex_trylock(mutex);
  }
  // Not part of any of the scenarios this rig currently drives - implement
  // only once a scenario actually needs it, so that its scheduling
  // semantics can be designed against a real use rather than guessed at.
  // Aborts directly, rather than throwing, because this is reached from
  // std::mutex::try_lock(), which is noexcept - an exception escaping it
  // would call std::terminate() anyway, with less control over the
  // diagnostic than doing so explicitly here.
  std::fprintf(
    stderr,
    "FATAL: pthread_mutex_trylock intercepted under an active "
    "DeterministicScheduler, but try_lock() is not yet implemented for "
    "scheduled scenarios\n");
  std::abort();
}
