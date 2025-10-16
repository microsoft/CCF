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

    WaitingWorkerThread(const WaitingWorkerThread&) = delete;
    WaitingWorkerThread& operator=(const WaitingWorkerThread&) = delete;

    WaitingWorkerThread(WaitingWorkerThread&&) = delete;
    WaitingWorkerThread& operator=(WaitingWorkerThread&&) = delete;

    ~WaitingWorkerThread()
    {
      // It is only safe to destruct a condition_variable if all threads have
      // been notified
      cv.notify_all();
    }
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

    // Collection describing idle worker threads. Owns structs used to assign
    // them incoming tasks
    std::vector<std::unique_ptr<WaitingWorkerThread>> waiting_worker_threads;

    // Collection of delayed tasks, that may be ready for execution on a future
    // tick
    Delayed delayed;

    void add_task(Task&& task)
    {
      // Under lock
      std::unique_lock<std::mutex> lock(mutex);

      // First check if there is an idle worker waiting for a task
      auto it = waiting_worker_threads.begin();
      if (it != waiting_worker_threads.end())
      {
        std::unique_ptr<WaitingWorkerThread>& worker = *it;

        // Assign this worker the incoming task, notify them, and then remove
        // their waiting state
        worker->assigned_task = std::move(task);
        worker->cv.notify_one();

        it = waiting_worker_threads.erase(it);
      }
      else
      {
        // There are no waiting_worker_threads currently, or none waiting for a
        // task, so enqueue this task for later execution
        pending_tasks.emplace(std::move(task));
      }
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
          // waiting_worker_threads and wait on a condition_variable. It will be
          // notified when a new Task is available
          auto waiting_worker =
            std::make_unique<WaitingWorkerThread>(to_return);

          // Maintain reference to a field in a unique ptr we're about to move.
          // This is only safe because we're under a mutex, and the only thing
          // that could destroy this object must first acquire the same mutex
          std::condition_variable& cv = waiting_worker->cv;

          // Transfer ownership to the central collection
          waiting_worker_threads.push_back(std::move(waiting_worker));

          // NOLINTBEGIN(bugprone-spuriously-wake-up-functions)
          // Spurious wakeup is acceptable, treated equivalently to timeout
          // elapsing
          cv.wait_for(lock, timeout);
          // NOLINTEND(bugprone-spuriously-wake-up-functions)

          // We reach here either because the condition_variable was notified,
          // or the timeout expired. In either case, return the (potentially
          // still null) assigned task

          // TODO: This doesn't work because we still need to cleanup if we
          // timed out/were spuriously woken!
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
