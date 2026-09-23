// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// cmake --build build --target locking_thread_safety
#include "ccf/ds/locking.h"

namespace
{
  struct ProtectedState
  {
    ccf::ds::SharedMutex mutex;
    int value CCF_GUARDED_BY(mutex) = 0;

    int read() CCF_REQUIRES_SHARED(mutex)
    {
      return value;
    }

    void write() CCF_REQUIRES(mutex)
    {
      ++value;
    }

    void exclusive() CCF_EXCLUDES(mutex)
    {
      ccf::ds::SharedMutexExclusiveGuard guard(mutex);
      write();
      (void)read();
      guard.unlock();
      // expected-error@+1 {{reading variable 'value'}}
      const int unguarded = value;
      (void)unguarded;
      guard.lock();
      write();
      std::condition_variable_any cv;
      cv.wait_for(guard, std::chrono::milliseconds(1));
      write();
    }

    void shared() CCF_EXCLUDES(mutex)
    {
      ccf::ds::SharedMutexReadGuard guard(mutex);
      (void)read();
      // expected-error@+1 {{requires holding mutex 'mutex' exclusively}}
      ++value;
      // expected-error@+1 {{requires holding mutex 'mutex' exclusively}}
      write();
      // expected-error@+1 {{cannot call function 'exclusive'}}
      exclusive();
    }

    void unlocked() CCF_EXCLUDES(mutex)
    {
      // expected-error@+1 {{reading variable 'value'}}
      const int unguarded = value;
      (void)unguarded;
      // expected-error@+1 {{calling function 'read'}}
      read();
      // expected-error@+1 {{requires holding mutex 'mutex' exclusively}}
      write();
    }

    void early_unlock() CCF_EXCLUDES(mutex)
    {
      ccf::ds::SharedMutexExclusiveGuard guard(mutex);
      write();
      guard.unlock();
    }
  };
}
