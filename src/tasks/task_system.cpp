// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/task_system.h"

#include "tasks/job_board.h"
#include "tasks/resumable.h"
#include "tasks/task.h"

#include <stdexcept>

namespace ccf::tasks
{
  // Implementation of BaseTask
  static thread_local BaseTask* current_task = nullptr;

  void BaseTask::do_task()
  {
    if (cancelled.load())
    {
      return;
    }

    ccf::tasks::current_task = this;

    do_task_implementation();

    ccf::tasks::current_task = nullptr;
  }

  ccf::tasks::Resumable BaseTask::pause()
  {
    return nullptr;
  }

  void BaseTask::cancel_task()
  {
    cancelled.store(true);
  }

  bool BaseTask::is_cancelled()
  {
    return cancelled.load();
  }

  // Implementation of ccf::tasks namespace static functions
  IJobBoard& get_main_job_board()
  {
    static JobBoard main_job_board;
    return main_job_board;
  }

  void add_task(Task task)
  {
    get_main_job_board().add_task(std::move(task));
  }

  void add_task_after(Task task, std::chrono::milliseconds ms)
  {
    // TODO: via uv_timer?
  }

  void add_periodic_task(
    Task task,
    std::chrono::milliseconds initial_delay,
    std::chrono::milliseconds perioidic_delay)
  {
    // TODO: via uv_timer
  }

  // From resumable.h
  Resumable pause_current_task()
  {
    if (current_task == nullptr)
    {
      throw std::logic_error("Cannot pause: No task currently running");
    }

    auto handle = current_task->pause();
    if (handle == nullptr)
    {
      throw std::logic_error("Cannot pause: Current task is not pausable");
    }

    return handle;
  }

  void resume_task(Resumable&& resumable)
  {
    resumable->resume();
  }
}