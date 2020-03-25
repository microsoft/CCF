// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifdef INSIDE_ENCLAVE
#  include <pthread.h>

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

  void unlock()
  {
    pthread_spin_unlock(&sl);
  }
};
#else
#  include <mutex>
using SpinLock = std::mutex;
#endif
