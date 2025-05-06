// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./looping_thread.h"

struct WorkerState
{
  IJobBoard& job_board;

  size_t tasks_done;
};

struct Worker : public LoopingThread<WorkerState>
{
  Worker(IJobBoard& jb, size_t idx) :
    LoopingThread<WorkerState>(fmt::format("w{}", idx), jb)
  {}

  ~Worker() override
  {
    shutdown();

    LOG_INFO_FMT(
      "Shutting down {}, processed {} tasks", name, state.tasks_done);
  }

  Stage loop_behaviour() override
  {
    // Wait (with timeout) for a task
    auto task = state.job_board.wait_for_task(std::chrono::milliseconds(10));
    if (task != nullptr)
    {
      task->do_task();
      ++state.tasks_done;
    }

    return Stage::Running;
  }
};
