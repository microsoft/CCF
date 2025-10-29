// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/job_board.h"

#include <atomic>
#include <chrono>

namespace ccf::tasks
{
  void task_worker_loop(JobBoard& job_board, std::atomic<bool>& stop_signal)
  {
    static constexpr auto wait_time = std::chrono::milliseconds(100);

    while (!stop_signal.load())
    {
      auto task = job_board.wait_for_task(wait_time);
      if (task != nullptr)
      {
        if (!task->is_cancelled())
        {
          task->do_task();
        }
      }
    }
  }
}