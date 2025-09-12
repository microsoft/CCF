// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/task_system.h"

static inline void flush_all_tasks(
  std::atomic<bool>& stop_signal,
  size_t worker_count,
  std::chrono::seconds kill_after = std::chrono::seconds(5))
{
  std::vector<std::thread> workers;
  for (size_t i = 0; i < worker_count; ++i)
  {
    workers.emplace_back([&stop_signal]() {
      while (!stop_signal.load())
      {
        auto task = ccf::tasks::get_main_job_board().get_task();
        if (task != nullptr)
        {
          task->do_task();
        }
        std::this_thread::yield();
      }
    });
  }

  using TClock = std::chrono::steady_clock;
  auto now = TClock::now();

  const auto hard_end = now + kill_after;

  while (true)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    now = TClock::now();
    if (now > hard_end)
    {
      break;
    }

    if (stop_signal.load())
    {
      break;
    }
  }

  stop_signal.store(true);

  for (auto& worker : workers)
  {
    worker.join();
  }
}