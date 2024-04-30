// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
#  include <mutex>
#else
#  include <openenclave/3rdparty/libc/pthread.h>
#  include <openenclave/edger8r/enclave.h> // For oe_lfence
#endif

namespace ccf::pal
{
#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)

  /**
   * Virtual enclaves and the host code share the same PAL.
   * This PAL takes no dependence on OpenEnclave, but also does not apply
   * security hardening.
   */
  using Mutex = std::mutex;

  static inline void speculation_barrier() {}

#else

  /**
   * Temporary workaround until the fix for
   * https://github.com/openenclave/openenclave/issues/4555 is available in a
   * release.
   */
  class MutexImpl
  {
  private:
    pthread_spinlock_t sl;

  public:
    MutexImpl()
    {
      pthread_spin_init(&sl, PTHREAD_PROCESS_PRIVATE);
    }

    ~MutexImpl()
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

  using Mutex = MutexImpl;

  static inline void speculation_barrier()
  {
    oe_lfence();
  }

#endif
}