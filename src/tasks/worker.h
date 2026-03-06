// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/internal_logger.h"
#include "tasks/job_board.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <string>

namespace ccf::tasks
{
  // Logs the error message and prints a demangled stacktrace to stderr.
  // Prefers the throw-point backtrace (captured via __cxa_throw interposition)
  // when available, otherwise falls back to a catch-point backtrace.
  void dump_stacktrace(const std::string& msg);

  inline void task_worker_loop(
    JobBoard& job_board,
    std::atomic<bool>& stop_signal,
    bool abort_on_throw = true)
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
            dump_stacktrace(fmt::format(
              "{} task failed with exception: {}", task->get_name(), e.what()));
            if (abort_on_throw)
            {
              std::abort();
            }
          }
          catch (...)
          {
            dump_stacktrace(fmt::format(
              "{} task failed with unknown exception", task->get_name()));
            if (abort_on_throw)
            {
              std::abort();
            }
          }
        }
      }
    }
  }
}