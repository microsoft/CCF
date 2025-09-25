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
  namespace
  {
    // Align by cacheline to avoid false sharing
    static constexpr size_t CACHELINE_SIZE = 64;

    template <typename T>
    struct alignas(CACHELINE_SIZE) CacheLineAligned
    {
      T value;
    };

    using StopSignal = CacheLineAligned<std::atomic<bool>>;

    void task_worker_loop(JobBoard& job_board, StopSignal& stop_signal)
    {
      static constexpr auto wait_time = std::chrono::milliseconds(100);

      while (!stop_signal.value.load())
      {
        auto task = job_board.wait_for_task(wait_time);
        if (task != nullptr)
        {
          if (!task->is_cancelled())
          {
            task->do_task();
          }
        }
      }
    }

    class ShiftSupervisor
    {
      static constexpr size_t MAX_WORKERS = 64;

      std::thread workers[MAX_WORKERS] = {};
      StopSignal stop_signals[MAX_WORKERS] = {};

      std::mutex worker_count_mutex;
      size_t current_workers = 0;

      JobBoard& job_board;

    public:
      ShiftSupervisor(JobBoard& job_board_) : job_board(job_board_) {}
      ~ShiftSupervisor()
      {
        set_worker_count(0);
      }

      void set_worker_count(size_t new_worker_count)
      {
        std::unique_lock<std::mutex> lock(worker_count_mutex);

        if (new_worker_count >= MAX_WORKERS)
        {
          throw std::logic_error(fmt::format(
            "Cannot create {} workers. Max permitted is {}",
            new_worker_count,
            MAX_WORKERS));
        }

        if (new_worker_count < current_workers)
        {
          // Stop workers
          // Do this in 2 loops, so that the stop_signals can be processed
          // concurrently
          for (auto i = new_worker_count; i < current_workers; ++i)
          {
            stop_signals[i].value.store(true);
          }

          for (auto i = new_worker_count; i < current_workers; ++i)
          {
            workers[i].join();
          }
        }
        else if (new_worker_count > current_workers)
        {
          // Start workers
          for (auto i = current_workers; i < new_worker_count; ++i)
          {
            auto& stop_signal = stop_signals[i];
            stop_signal.value.store(false);
            workers[i] = std::thread(
              task_worker_loop, std::ref(job_board), std::ref(stop_signal));
          }
        }

        current_workers = new_worker_count;
      }
    };
  }

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
    static ShiftSupervisor shift_supervisor(get_main_job_board());
    shift_supervisor.set_worker_count(new_worker_count);
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