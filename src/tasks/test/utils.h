// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/job_board.h"

#include <atomic>

namespace test::utils
{
  static inline void worker_loop_func(
    ccf::tasks::JobBoard& job_board, std::atomic<bool>& stop)
  {
    while (!stop.load())
    {
      auto task = job_board.get_task();
      if (task != nullptr)
      {
        task->do_task();
      }
      std::this_thread::yield();
    }
  }

  static inline void flush_board(
    ccf::tasks::JobBoard& job_board,
    size_t max_workers = 8,
    std::function<bool(void)> safe_to_end = nullptr,
    std::chrono::seconds kill_after = std::chrono::seconds(5))
  {
    std::atomic<bool> stop_signal{false};

    std::vector<std::thread> workers;
    for (size_t i = 0; i < max_workers; ++i)
    {
      workers.emplace_back(
        worker_loop_func, std::ref(job_board), std::ref(stop_signal));
    }

    using TClock = std::chrono::steady_clock;
    auto now = TClock::now();
    const auto end_time = now + std::chrono::seconds(1);
    const auto hard_end = now + kill_after;

    if (safe_to_end == nullptr)
    {
      safe_to_end = [&]() { return now > end_time; };
      // safe_to_end = [&]() { return now > end_time && job_board.empty(); };
    }

    while (true)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      now = TClock::now();
      if (now > hard_end)
      {
        break;
      }

      if (safe_to_end())
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
}
