// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/internal_logger.h"
#include "tasks/job_board.h"

#include <atomic>
#include <chrono>
#include <exception>

namespace ccf::tasks
{
  inline void task_worker_loop(
    JobBoard& job_board, std::atomic<bool>& stop_signal)
  {
    static constexpr auto wait_time = std::chrono::milliseconds(100);

    while (!stop_signal.load())
    {
      auto task = job_board.wait_for_task(wait_time);
      if (task != nullptr)
      {
        if (!task->is_cancelled())
        {
          try
          {
            task->do_task();
          }
          catch (const std::exception& e)
          {
            LOG_FAIL_FMT(
              "{} task failed with exception: {}", task->get_name(), e.what());
          }
          catch (...)
          {
            LOG_FAIL_FMT(
              "{} task failed with unknown exception", task->get_name());
          }
        }
      }
    }
  }
}