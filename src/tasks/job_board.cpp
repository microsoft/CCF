// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "tasks/job_board.h"

#include <chrono>
#include <map>

namespace ccf::tasks
{
  struct Consumer
  {
    // Temporary structure
    // NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
    Task& task;
    std::condition_variable& cv;
    // NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)
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
    std::mutex mutex;
    std::queue<Task> pending_tasks;
    std::vector<Consumer*> waiting_consumers;

    Delayed delayed;

    void add_task(Task&& task)
    {
      std::unique_lock<std::mutex> lock(mutex);

      for (Consumer* consumer : waiting_consumers)
      {
        // NB: Although waiting_consumers is modified under lock, it's possible
        // that another call to add_task arrives the notified thread wakes up
        // and removes itself from this collection. In this case we must avoid
        // overwriting a previously-assigned task.
        if (consumer->task == nullptr)
        {
          consumer->task = std::move(task);
          consumer->cv.notify_one();
          return;
        }
      }

      // There are no waiting_consumers currently, or none waiting for a task
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
        std::unique_lock<std::mutex> lock(mutex);

        if (pending_tasks.empty())
        {
          std::condition_variable cv;
          auto consumer = std::make_unique<Consumer>(to_return, cv);
          waiting_consumers.push_back(consumer.get());

          cv.wait_for(lock, timeout);

          // TODO: What if this resume happens after destructor? Do we need to
          // extend lifetime of PImpl?
          auto it = std::find(
            waiting_consumers.begin(), waiting_consumers.end(), consumer.get());
          waiting_consumers.erase(it);
        }
        else
        {
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
      summary.idle_workers = pimpl->waiting_consumers.size();
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
