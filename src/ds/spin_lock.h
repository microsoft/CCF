// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifdef INSIDE_ENCLAVE
#  include <pthread.h>

// OpenEnclave, at this time, does not provide pthread_spin_trylock. There is
// currently a PR that will introduce said function and this should be removed
// when said function is in OpenEnclave.
// https://github.com/openenclave/openenclave/pull/3641
#  ifndef VIRTUAL_ENCLAVE
static unsigned int _spin_set_locked(pthread_spinlock_t* spinlock)
{
  unsigned int value = 1;

  asm volatile("lock xchg %0, %1;"
               : "=r"(value) /* %0 */
               : "m"(*spinlock), /* %1 */
                 "0"(value) /* also %2 */
               : "memory");

  return value;
}
#  endif

class SpinLock
{
private:
  pthread_spinlock_t sl;

public:
  SpinLock()
  {
    pthread_spin_init(&sl, PTHREAD_PROCESS_PRIVATE);
  }

  ~SpinLock()
  {
    pthread_spin_destroy(&sl);
  }

  void lock()
  {
    pthread_spin_lock(&sl);
  }

  bool try_lock()
  {
#  ifdef VIRTUAL_ENCLAVE
    return pthread_spin_trylock(&sl) == 0;
#  else
    return (_spin_set_locked(&sl) == 0);
#  endif
  }

  void unlock()
  {
    pthread_spin_unlock(&sl);
  }
};
#else
#  include <mutex>
using SpinLock = std::mutex;
#endif
