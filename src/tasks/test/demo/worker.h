// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./looping_thread.h"

struct WorkerState
{
  ccf::tasks::IJobBoard& job_board;

  size_t work_completed;

  std::atomic<bool> consider_termination = false;
};

struct Worker : public LoopingThread<WorkerState>
{
  Worker(ccf::tasks::IJobBoard& jb, size_t idx) :
    LoopingThread<WorkerState>(fmt::format("w{}", idx), jb)
  {}

  ~Worker() override
  {
    shutdown();

    LOG_INFO_FMT(
      "Shutting down {}, processed {} tasks", name, state.work_completed);
  }

  Stage loop_behaviour() override
  {
    // Wait (with timeout) for a task
    auto task = state.job_board.wait_for_task(std::chrono::milliseconds(10));
    if (task != nullptr)
    {
      state.work_completed += task->do_task();
    }
    else if (state.consider_termination.load())
    {
      return Stage::Terminated;
    }

    return Stage::Running;
  }
};
