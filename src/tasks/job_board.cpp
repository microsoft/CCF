// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "tasks/job_board.h"

namespace ccf::tasks
{
  void JobBoard::add_task(Task&& t)
  {
    {
      std::lock_guard<std::mutex> lock(mutex);
      queue.emplace(std::move(t));
    }
    work_beacon.notify_work_available();
  }

  Task JobBoard::get_task()
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

  bool JobBoard::empty()
  {
    std::lock_guard<std::mutex> lock(mutex);
    return queue.empty();
  }

  Task JobBoard::wait_for_task(const std::chrono::milliseconds& timeout)
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
}
