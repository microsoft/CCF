// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// clang++ -std=c++23 -Iinclude -Wthread-safety -Xclang -verify -fsyntax-only \
//   src/ds/test/locking_thread_safety.cpp
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
      ccf::ds::SharedMutexGuard guard(mutex);
      write();
      (void)read();
      guard.unlock();
      // expected-warning@+1 {{reading variable 'value'}}
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
      // expected-warning@+1 {{requires holding mutex 'mutex' exclusively}}
      ++value;
      // expected-warning@+1 {{requires holding mutex 'mutex' exclusively}}
      write();
      // expected-warning@+1 {{cannot call function 'exclusive'}}
      exclusive();
    }

    void unlocked() CCF_EXCLUDES(mutex)
    {
      // expected-warning@+1 {{reading variable 'value'}}
      const int unguarded = value;
      (void)unguarded;
      // expected-warning@+1 {{calling function 'read'}}
      read();
      // expected-warning@+1 {{requires holding mutex 'mutex' exclusively}}
      write();
    }

    void early_unlock() CCF_EXCLUDES(mutex)
    {
      ccf::ds::SharedMutexGuard guard(mutex);
      write();
      guard.unlock();
    }
  };
}
