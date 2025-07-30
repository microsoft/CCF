// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/job_board_interface.h"
#include "tasks/resumable.h"
#include "tasks/task.h"

namespace ccf::tasks
{
  IJobBoard& get_main_job_board();

  void add_task(Task task);
  void add_task_after(Task task, std::chrono::milliseconds ms);

  void add_periodic_task(
    Task task,
    std::chrono::milliseconds initial_delay,
    std::chrono::milliseconds perioidic_delay);

  inline void add_periodic_task(Task task, std::chrono::milliseconds period)
  {
    add_periodic_task(task, period, period);
  }

  // TODO: How to pass time to this central, delayed queueuer? Is
  // that a separate subsystem or something?
  void tick();
}