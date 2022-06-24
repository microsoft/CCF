// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#if defined(INSIDE_ENCLAVE) && !defined(VIRTUAL_ENCLAVE)
#  include <pthread.h>

namespace ccf
{
  class Mutex
  {
  private:
    pthread_spinlock_t sl;

  public:
    Mutex()
    {
      pthread_spin_init(&sl, PTHREAD_PROCESS_PRIVATE);
    }

    ~Mutex()
    {
      pthread_spin_destroy(&sl);
    }

    void lock()
    {
      pthread_spin_lock(&sl);
    }

    bool try_lock()
    {
      return pthread_spin_trylock(&sl) == 0;
    }

    void unlock()
    {
      pthread_spin_unlock(&sl);
    }
  };
}

#else
#  include <mutex>

namespace ccf
{
  using Mutex = std::mutex;
}
#endif