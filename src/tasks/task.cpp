// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/task.h"

#include <stdexcept>

namespace ccf::tasks
{
  size_t BaseTask::do_task()
  {
    if (cancelled.load())
    {
      return 0;
    }

    ccf::tasks::current_task = this;

    const auto n = do_task_implementation();

    ccf::tasks::current_task = nullptr;

    return n;
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

  using Task = std::shared_ptr<BaseTask>;

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