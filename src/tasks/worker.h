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
  // Logs the error message and a demangled throw-point stacktrace when
  // available.
  void dump_stacktrace(const std::string& msg);

  // Executes a task with exception handling. On any exception, logs a
  // stacktrace and aborts (unless abort_on_throw is false).
  inline void try_do_task(BaseTask& task, bool abort_on_throw = true)
  {
    if (task.is_cancelled())
    {
      return;
    }

    try
    {
      task.do_task();
    }
    catch (const std::exception& e)
    {
      dump_stacktrace(fmt::format(
        "{} task failed with exception: {}", task.get_name(), e.what()));
      if (abort_on_throw)
      {
        std::abort();
      }
    }
    catch (...)
    {
      dump_stacktrace(
        fmt::format("{} task failed with unknown exception", task.get_name()));
      if (abort_on_throw)
      {
        std::abort();
      }
    }
  }

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
        try_do_task(*task, abort_on_throw);
      }
    }
  }
}