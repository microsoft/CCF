// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./looping_thread.h"

struct Worker : public LoopingThread
{
  IJobBoard& job_board;

  Worker(IJobBoard& jb, size_t idx) :
    LoopingThread(fmt::format("w{}", idx)),
    job_board(jb)
  {}

  bool loop_behaviour() override
  {
    // Wait at-most 100ms for a task
    auto task = job_board.wait_for_task(std::chrono::milliseconds(100));
    if (task != nullptr)
    {
      task->do_task();
    }

    return false;
  }
};
