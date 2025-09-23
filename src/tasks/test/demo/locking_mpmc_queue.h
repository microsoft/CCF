// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <deque>
#include <mutex>

namespace ccf::tasks
{
  // A very simple (slow) MPMPC queue, implemented by a std container guarded by
  // a mutex
  template <typename T>
  class LockingMPMCQueue
  {
  protected:
    std::mutex mutex;
    std::deque<T> deque;

  public:
    bool empty()
    {
      std::lock_guard<std::mutex> lock(mutex);
      return deque.empty();
    }

    size_t size()
    {
      std::lock_guard<std::mutex> lock(mutex);
      return deque.size();
    }

    void push_back(const T& t)
    {
      std::lock_guard<std::mutex> lock(mutex);
      deque.push_back(t);
    }

    void emplace_back(T&& t)
    {
      std::lock_guard<std::mutex> lock(mutex);
      deque.emplace_back(std::move(t));
    }

    std::optional<T> try_pop()
    {
      std::lock_guard<std::mutex> lock(mutex);

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
