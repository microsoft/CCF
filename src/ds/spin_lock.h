// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifdef INSIDE_ENCLAVE
#  include <pthread.h>
   static unsigned int _spin_set_locked(pthread_spinlock_t* spinlock)
{
    unsigned int value = 1;

    asm volatile("lock xchg %0, %1;"
                 : "=r"(value)     /* %0 */
                 : "m"(*spinlock), /* %1 */
                   "0"(value)      /* also %2 */
                 : "memory");

    return value;
}

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
    return (_spin_set_locked(&sl) == 0);
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
