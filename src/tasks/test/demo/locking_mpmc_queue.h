// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/locking.h"

#include <deque>

namespace ccf::tasks
{
  // A very simple (slow) MPMPC queue, implemented by a std container guarded by
  // a mutex
  template <typename T>
  class LockingMPMCQueue
  {
  protected:
    ccf::pal::Mutex mutex;
    std::deque<T> deque CCF_GUARDED_BY(mutex);

  public:
    bool empty()
    {
      ccf::pal::MutexGuard lock(mutex);
      return deque.empty();
    }

    size_t size()
    {
      ccf::pal::MutexGuard lock(mutex);
      return deque.size();
    }

    void push_back(const T& t)
    {
      ccf::pal::MutexGuard lock(mutex);
      deque.push_back(t);
    }

    void emplace_back(T&& t)
    {
      ccf::pal::MutexGuard lock(mutex);
      deque.emplace_back(std::move(t));
    }

    std::optional<T> try_pop()
    {
      ccf::pal::MutexGuard lock(mutex);

      if (deque.empty())
      {
        return std::nullopt;
      }

      std::optional<T> val = deque.front();
      deque.pop_front();
      return val;
    }
  };
}
