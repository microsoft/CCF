// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/queues/concurrent_queue_interface.h"

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

    std::string describe_queue() const
    {
      return fmt::format("{}", fmt::join(deque, ", "));
    }

  public:
    bool empty() override
    {
      std::lock_guard<std::mutex> lock(mutex);
      return deque.empty();
    }

    void push_back(const T& t) override
    {
      std::lock_guard<std::mutex> lock(mutex);
      deque.push_back(t);
      LOG_INFO_FMT("After push_back, queue is: {}", describe_queue());
    }

    void emplace_back(T&& t) override
    {
      std::lock_guard<std::mutex> lock(mutex);
      deque.emplace_back(std::move(t));
      LOG_INFO_FMT("After emplace_back, queue is: {}", describe_queue());
    }

    std::optional<T> try_pop() override
    {
      std::lock_guard<std::mutex> lock(mutex);

      if (deque.empty())
      {
        return std::nullopt;
      }

      LOG_INFO_FMT("Before pop_front, queue is: {}", describe_queue());
      std::optional<T> val = deque.front();
      deque.pop_front();
      return val;
    }
  };
}
