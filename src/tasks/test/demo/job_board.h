// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./task.h"

#include <mutex>
#include <queue>
#include <thread>

struct IJobBoard
{
  virtual void add_task(Task&& t) = 0;
  virtual Task get_task() = 0;
  virtual bool empty() = 0;

  virtual Task wait_for_task(const std::chrono::milliseconds& timeout) = 0;
};

struct JobBoard : public IJobBoard
{
  std::mutex mutex;
  std::queue<Task> queue;

  void add_task(Task&& t) override
  {
    std::lock_guard<std::mutex> lock(mutex);
    queue.emplace(std::move(t));
  }

  Task get_task() override
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (queue.empty())
    {
      return nullptr;
    }

    Task t = queue.front();
    queue.pop();
    return t;
  }

  bool empty() override
  {
    std::lock_guard<std::mutex> lock(mutex);
    return queue.empty();
  }

  Task wait_for_task(const std::chrono::milliseconds& timeout) override
  {
    // TODO: Add a condition_variable to remove spinloop
    using TClock = std::chrono::system_clock;

    const auto start = TClock::now();
    const auto until = start + timeout;

    while (true)
    {
      auto task = get_task();
      if (task != nullptr || TClock::now() >= until)
      {
        return task;
      }

      std::this_thread::yield();
    }
  }
};