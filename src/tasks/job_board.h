// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./task.h"
#include "ds/work_beacon.h"

#include <mutex>
#include <queue>
#include <thread>

namespace ccf::tasks
{
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
    ccf::ds::WorkBeacon work_beacon;

    void add_task(Task&& t) override
    {
      {
        std::lock_guard<std::mutex> lock(mutex);
        queue.emplace(std::move(t));
      }
      work_beacon.notify_work_available();
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

        work_beacon.wait_for_work_with_timeout(timeout);
      }
    }
  };
}
