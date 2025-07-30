// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/task_system.h"

#include "ccf/ds/logger.h"
#include "tasks/job_board.h"
#include "tasks/resumable.h"
#include "tasks/task.h"

#include <stdexcept>
#include <uv.h>

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

  struct TaskLifetime
  {
    Task task;
  };

  static void uv_timer_cb(uv_timer_t* handle)
  {
    auto* lifetime = (TaskLifetime*)handle->data;
    add_task(lifetime->task);

    const auto repeat = uv_timer_get_repeat(handle);
    if (repeat == 0)
    {
      delete lifetime;
      delete handle;
    }
  }

  void add_task_via_uv_callback(
    Task task,
    std::chrono::milliseconds initial_delay,
    std::chrono::milliseconds repeat_period)
  {
    // TODO: The lifetime of this handle is rubbish. Can we make the caller
    // responsible for it?
    uv_timer_t* uv_handle = new uv_timer_t;

    int rc;
    rc = uv_timer_init(uv_default_loop(), uv_handle);
    if (rc < 0)
    {
      LOG_FAIL_FMT("uv_timer_init failed: {}", uv_strerror(rc));
      delete uv_handle;
      throw std::logic_error("uv_timer_init failed");
    }

    uv_handle->data = new TaskLifetime{task};

    rc = uv_timer_start(
      uv_handle, uv_timer_cb, initial_delay.count(), repeat_period.count());
    if (rc < 0)
    {
      LOG_FAIL_FMT("uv_timer_start failed: {}", uv_strerror(rc));
      delete uv_handle;
      throw std::logic_error("uv_timer_start failed");
    }
  }

  void add_task_after(Task task, std::chrono::milliseconds delay)
  {
    add_task_via_uv_callback(task, delay, {});
  }

  void add_periodic_task(
    Task task,
    std::chrono::milliseconds initial_delay,
    std::chrono::milliseconds repeat_period)
  {
    add_task_via_uv_callback(task, initial_delay, repeat_period);
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