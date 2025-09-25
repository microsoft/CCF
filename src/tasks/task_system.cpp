// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/task_system.h"

#include "ds/internal_logger.h"
#include "tasks/job_board.h"
#include "tasks/resumable.h"
#include "tasks/task.h"
#include "tasks/thread_manager.h"

#include <stdexcept>
#include <uv.h>

namespace ccf::tasks
{
  // Implementation of BaseTask
  namespace
  {
    thread_local BaseTask* current_task = nullptr;
  }

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
  JobBoard& get_main_job_board()
  {
    static JobBoard main_job_board;
    return main_job_board;
  }

  void set_worker_count(size_t new_worker_count)
  {
    static ThreadManager thread_manager(get_main_job_board());
    thread_manager.set_worker_count(new_worker_count);
  }

  void add_task(Task task)
  {
    get_main_job_board().add_task(std::move(task));
  }

  void add_delayed_task(Task task, std::chrono::milliseconds delay)
  {
    get_main_job_board().add_delayed_task(std::move(task), delay);
  }

  void add_periodic_task(
    Task task,
    std::chrono::milliseconds initial_delay,
    std::chrono::milliseconds repeat_period)
  {
    get_main_job_board().add_periodic_task(
      std::move(task), initial_delay, repeat_period);
  }

  void tick(std::chrono::milliseconds elapsed)
  {
    get_main_job_board().tick(elapsed);
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