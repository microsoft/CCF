// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/task_system.h"

#include "ds/internal_logger.h"
#include "tasks/job_board.h"
#include "tasks/resumable.h"
#include "tasks/task.h"

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

  void add_task(Task task)
  {
    get_main_job_board().add_task(std::move(task));
  }

  struct DelayedTask
  {
    Task task;
    std::optional<std::chrono::milliseconds> repeat = std::nullopt;
  };

  using DelayedTasks = std::vector<DelayedTask>;

  using DelayedTasksByTime = std::map<std::chrono::milliseconds, DelayedTasks>;

  using namespace std::chrono_literals;

  namespace
  {
    std::atomic<std::chrono::milliseconds> total_elapsed = 0ms;

    DelayedTasksByTime delayed_tasks;
    std::mutex delayed_tasks_mutex;
  }

  void add_delayed_task(
    Task task,
    std::chrono::milliseconds initial_delay,
    std::optional<std::chrono::milliseconds> periodic_delay)
  {
    std::lock_guard<std::mutex> lock(delayed_tasks_mutex);

    const auto trigger_time = total_elapsed.load() + initial_delay;
    delayed_tasks[trigger_time].emplace_back(task, periodic_delay);
  }

  void add_delayed_task(Task task, std::chrono::milliseconds delay)
  {
    add_delayed_task(task, delay, std::nullopt);
  }

  void add_periodic_task(
    Task task,
    std::chrono::milliseconds initial_delay,
    std::chrono::milliseconds repeat_period)
  {
    add_delayed_task(task, initial_delay, repeat_period);
  }

  void tick(std::chrono::milliseconds elapsed)
  {
    elapsed += total_elapsed.load();

    {
      std::lock_guard<std::mutex> lock(delayed_tasks_mutex);
      auto end_it = delayed_tasks.upper_bound(elapsed);

      DelayedTasksByTime repeats;

      for (auto it = delayed_tasks.begin(); it != end_it; ++it)
      {
        DelayedTasks& ready = it->second;

        for (DelayedTask& delayed_task : ready)
        {
          // Don't schedule (or repeat) cancelled tasks
          if (delayed_task.task->is_cancelled())
          {
            continue;
          }

          add_task(delayed_task.task);
          if (delayed_task.repeat.has_value())
          {
            repeats[elapsed + delayed_task.repeat.value()].emplace_back(
              delayed_task);
          }
        }
      }

      delayed_tasks.erase(delayed_tasks.begin(), end_it);

      for (auto&& [repeat_time, repeated_tasks] : repeats)
      {
        DelayedTasks& delayed_tasks_at_time = delayed_tasks[repeat_time];
        delayed_tasks_at_time.insert(
          delayed_tasks_at_time.end(),
          repeated_tasks.begin(),
          repeated_tasks.end());
      }
    }

    total_elapsed.store(elapsed);
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