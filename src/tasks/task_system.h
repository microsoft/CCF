// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/job_board.h"
#include "tasks/resumable.h"
#include "tasks/task.h"

namespace ccf::tasks
{
  JobBoard& get_main_job_board();

  void add_task(Task task);

  void add_delayed_task(Task task, std::chrono::milliseconds delay);

  void add_periodic_task(
    Task task,
    std::chrono::milliseconds initial_delay,
    std::chrono::milliseconds repeat_period);

  void tick(std::chrono::milliseconds elapsed);
}