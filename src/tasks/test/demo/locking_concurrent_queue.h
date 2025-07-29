// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./concurrent_queue_interface.h"

#include <deque>
#include <mutex>

namespace ccf::tasks
{
  template <typename T>
  class LockingConcurrentQueue : public IConcurrentQueue<T>
  {
  protected:
    std::mutex mutex;
    std::deque<T> deque;

  public:
    bool empty() override
    {
      std::lock_guard<std::mutex> lock(mutex);
      return deque.empty();
    }

    size_t size()
    {
      std::lock_guard<std::mutex> lock(mutex);
      return deque.size();
    }

    void push_back(const T& t) override
    {
      std::lock_guard<std::mutex> lock(mutex);
      deque.push_back(t);
    }

    void emplace_back(T&& t) override
    {
      std::lock_guard<std::mutex> lock(mutex);
      deque.emplace_back(std::move(t));
    }

    std::optional<T> try_pop() override
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
