// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "tasks/job_board.h"

#include <chrono>
#include <map>

namespace ccf::tasks
{
  // Temporary struct used by idle worker threads when no tasks are available.
  // See wait_for_task and add_task for useage.
  struct WaitingWorkerThread
  {
    // Ownership of a condition variable that a single thread will wait on
    std::condition_variable cv;

    // Output variable to assign that thread a task
    Task& assigned_task;

    WaitingWorkerThread(Task& at_) : assigned_task(at_) {}
  };

  struct Delayed
  {
    struct DelayedTask
    {
      Task task;
      std::optional<std::chrono::milliseconds> repeat = std::nullopt;
    };

    using DelayedTasks = std::vector<DelayedTask>;

    using DelayedTasksByTime =
      std::map<std::chrono::milliseconds, DelayedTasks>;

    std::atomic<std::chrono::milliseconds> total_elapsed =
      std::chrono::milliseconds(0);

    std::mutex tasks_mutex;
    DelayedTasksByTime tasks;
  };

  struct JobBoard::PImpl
  {
    // Mutex protects access to both pending_tasks and waiting_worker_threads
    std::mutex mutex;

    // Collection of tasks that are ready for execution
    std::queue<Task> pending_tasks;

    // Collection describing idle worker threads. This is a non-owning pointer,
    // with the lifetime managed by the caller, who should ensure the object
    // outlives the pointer's presence in this collection
    std::vector<WaitingWorkerThread*> waiting_worker_threads;

    // Collection of delayed tasks, that may be ready for execution on a future
    // tick
    Delayed delayed;

    void add_task(Task&& task)
    {
      // Under lock
      std::unique_lock<std::mutex> lock(mutex);

      // First check if there is an idle worker waiting for a task
      for (WaitingWorkerThread* worker : waiting_worker_threads)
      {
        // NB: Although waiting_worker_threads is modified under lock, it's
        // possible that a second call to add_task arrives before the notified
        // thread wakes up and removes itself from this collection. In this case
        // we must avoid overwriting a previously-assigned task.
        if (worker->assigned_task == nullptr)
        {
          worker->assigned_task = std::move(task);
          worker->cv.notify_one();
          return;
        }
      }

      // There are no waiting_worker_threads currently, or none waiting for a
      // task, so enqueue this task for later execution
      pending_tasks.emplace(std::move(task));
    }

    Task get_task()
    {
      using namespace std::chrono_literals;
      return wait_for_task(0ms);
    }

    Task wait_for_task(const std::chrono::milliseconds& timeout)
    {
      Task to_return = nullptr;

      {
        // Under lock
        std::unique_lock<std::mutex> lock(mutex);

        // Check if there are pending tasks to be executed
        if (pending_tasks.empty())
        {
          // When the task queue is empty, append this thread to
          // waiting_worker_threads and wait on a condition_variable
          std::unique_ptr<WaitingWorkerThread> waiting_worker =
            std::make_unique<WaitingWorkerThread>(to_return);

          // Append local object to central collection
          waiting_worker_threads.push_back(waiting_worker.get());

          // NOLINTBEGIN(bugprone-spuriously-wake-up-functions)
          // Spurious wakeup is acceptable, treated equivalently to timeout
          // elapsing
          waiting_worker->cv.wait_for(lock, timeout);
          // NOLINTEND(bugprone-spuriously-wake-up-functions)

          // We reach here either because the condition_variable was notified,
          // or the timeout expired. In either case, we're responsible for
          // removing ourselves from the central collection, and then returning
          // the (potentially still null) assigned task
          auto it = std::find(
            waiting_worker_threads.begin(),
            waiting_worker_threads.end(),
            waiting_worker.get());
          waiting_worker_threads.erase(it);
        }
        else
        {
          // When the task queue is non-empty, take the first element from it
          to_return = pending_tasks.front();
          pending_tasks.pop();
        }
      }

      return to_return;
    }

    void add_timed_task(
      Task task,
      std::chrono::milliseconds initial_delay,
      std::optional<std::chrono::milliseconds> periodic_delay)
    {
      std::lock_guard<std::mutex> lock(delayed.tasks_mutex);

      const auto trigger_time = delayed.total_elapsed.load() + initial_delay;
      delayed.tasks[trigger_time].emplace_back(task, periodic_delay);
    }

    void tick(std::chrono::milliseconds elapsed)
    {
      elapsed += delayed.total_elapsed.load();

      {
        std::lock_guard<std::mutex> lock(delayed.tasks_mutex);
        auto end_it = delayed.tasks.upper_bound(elapsed);

        Delayed::DelayedTasksByTime repeats;

        for (auto it = delayed.tasks.begin(); it != end_it; ++it)
        {
          Delayed::DelayedTasks& ready = it->second;

          for (Delayed::DelayedTask& delayed_task : ready)
          {
            // Don't schedule (or repeat) cancelled tasks
            if (delayed_task.task->is_cancelled())
            {
              continue;
            }

            Task task_copy(delayed_task.task);
            add_task(std::move(task_copy));
            if (delayed_task.repeat.has_value())
            {
              repeats[elapsed + delayed_task.repeat.value()].emplace_back(
                delayed_task);
            }
          }
        }

        delayed.tasks.erase(delayed.tasks.begin(), end_it);

        for (auto&& [repeat_time, repeated_tasks] : repeats)
        {
          Delayed::DelayedTasks& delayed_tasks_at_time =
            delayed.tasks[repeat_time];
          delayed_tasks_at_time.insert(
            delayed_tasks_at_time.end(),
            repeated_tasks.begin(),
            repeated_tasks.end());
        }
      }

      delayed.total_elapsed.store(elapsed);
    }
  };

  void JobBoard::add_timed_task(
    Task task,
    std::chrono::milliseconds initial_delay,
    std::optional<std::chrono::milliseconds> periodic_delay)
  {
    pimpl->add_timed_task(std::move(task), initial_delay, periodic_delay);
  }

  JobBoard::JobBoard() : pimpl(std::make_unique<PImpl>()) {}

  JobBoard::~JobBoard() = default;

  void JobBoard::add_task(Task task)
  {
    pimpl->add_task(std::move(task));
  }

  Task JobBoard::get_task()
  {
    return pimpl->get_task();
  }

  Task JobBoard::wait_for_task(const std::chrono::milliseconds& timeout)
  {
    return pimpl->wait_for_task(timeout);
  }

  JobBoard::Summary JobBoard::get_summary()
  {
    Summary summary{};
    {
      std::lock_guard<std::mutex> lock(pimpl->mutex);
      summary.pending_tasks = pimpl->pending_tasks.size();
      summary.idle_workers = pimpl->waiting_worker_threads.size();
    }
    return summary;
  }

  void JobBoard::add_delayed_task(Task task, std::chrono::milliseconds delay)
  {
    add_timed_task(task, delay, std::nullopt);
  }

  void JobBoard::add_periodic_task(
    Task task,
    std::chrono::milliseconds initial_delay,
    std::chrono::milliseconds repeat_period)
  {
    add_timed_task(task, initial_delay, repeat_period);
  }

  void JobBoard::tick(std::chrono::milliseconds elapsed)
  {
    pimpl->tick(elapsed);
  }
}
