// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "tasks/job_board.h"

#include "ccf/ds/locking.h"

#include <chrono>
#include <map>
#include <unordered_map>

namespace ccf::tasks
{
  // Temporary struct used by idle worker threads when no tasks are available.
  // See wait_for_task and add_task for usage.
  struct WaitingWorkerThread
  {
    // Ownership of a condition variable that a single thread will wait on
    ccf::ds::ConditionVariable cv;

    // Output variable to assign that thread a task
    Task& assigned_task;

    // Reserved executors accept only critical tasks
    const bool critical_only;

    WaitingWorkerThread(Task& at_, bool critical_only_) :
      assigned_task(at_),
      critical_only(critical_only_)
    {}

    WaitingWorkerThread(const WaitingWorkerThread&) = delete;
    WaitingWorkerThread& operator=(const WaitingWorkerThread&) = delete;

    WaitingWorkerThread(WaitingWorkerThread&&) = delete;
    WaitingWorkerThread& operator=(WaitingWorkerThread&&) = delete;

    ~WaitingWorkerThread()
    {
      // Ensure all waiters are notified before destruction
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

    ccf::ds::Mutex tasks_mutex;
    std::chrono::milliseconds total_elapsed CCF_GUARDED_BY(tasks_mutex) =
      std::chrono::milliseconds(0);
    DelayedTasksByTime tasks CCF_GUARDED_BY(tasks_mutex);
    bool shut_down CCF_GUARDED_BY(tasks_mutex) = false;
  };

  struct JobBoard::Registry
  {
    ccf::ds::Mutex mutex;
    std::unordered_map<BaseTask*, std::weak_ptr<BaseTask>> tasks
      CCF_GUARDED_BY(mutex);
    bool shut_down CCF_GUARDED_BY(mutex) = false;
  };

  struct JobBoard::PImpl
  {
    // Mutex protects access to the pending queues and waiting_worker_threads
    ccf::ds::Mutex mutex;

    // Collections of tasks that are ready for execution, by TaskClass
    std::queue<Task> pending_tasks CCF_GUARDED_BY(mutex);
    std::queue<Task> pending_critical_tasks CCF_GUARDED_BY(mutex);

    // Collection describing idle worker threads. This takes shared pointers, to
    // ensure the objects remain valid even if the caller exits exceptionally
    // (without cleanup). Additionally the collection itself is owned by a
    // shared pointer, so that the caller can ensure the lifetime persists past
    // a condition_variable wait.
    using WorkerThreadPtr = std::shared_ptr<WaitingWorkerThread>;
    std::shared_ptr<std::vector<WorkerThreadPtr>> waiting_worker_threads
      CCF_GUARDED_BY(mutex) = std::make_shared<std::vector<WorkerThreadPtr>>();

    ccf::ds::WorkBeaconPtr work_beacon CCF_GUARDED_BY(mutex) = nullptr;
    ccf::ds::WorkBeaconPtr critical_work_beacon CCF_GUARDED_BY(mutex) = nullptr;
    bool stopping CCF_GUARDED_BY(mutex) = false;
    bool shut_down CCF_GUARDED_BY(mutex) = false;
    std::shared_ptr<Registry> registry = std::make_shared<Registry>();

    // Collection of tasks that become runnable at future deadlines
    Delayed delayed;

    void set_work_beacon(ccf::ds::WorkBeaconPtr work_beacon_)
    {
      ccf::ds::WorkBeaconPtr beacon;
      {
        ccf::ds::MutexGuard lock(mutex);
        work_beacon = std::move(work_beacon_);
        if (work_beacon != nullptr && !no_pending_tasks())
        {
          beacon = work_beacon;
        }
      }

      if (beacon != nullptr)
      {
        beacon->notify_work_available_coalesced();
      }
    }

    void set_critical_work_beacon(ccf::ds::WorkBeaconPtr work_beacon_)
    {
      ccf::ds::WorkBeaconPtr beacon;
      {
        ccf::ds::MutexGuard lock(mutex);
        critical_work_beacon = std::move(work_beacon_);
        if (critical_work_beacon != nullptr && !pending_critical_tasks.empty())
        {
          beacon = critical_work_beacon;
        }
      }

      if (beacon != nullptr)
      {
        beacon->notify_work_available_coalesced();
      }
    }

    [[nodiscard]] bool no_pending_tasks() const CCF_REQUIRES(mutex)
    {
      return pending_tasks.empty() && pending_critical_tasks.empty();
    }

    // Hands task to an idle worker able to run it, preferring critical-only
    // workers for critical tasks so general capacity stays available.
    bool assign_to_waiting_worker(Task& task, bool critical) CCF_REQUIRES(mutex)
    {
      // NB: Although waiting_worker_threads is modified under lock, it is
      // possible that a second call to add_task arrives before the notified
      // thread wakes up and removes itself from this collection. In this case
      // we must avoid overwriting a previously-assigned task.
      for (const bool want_critical_only : {true, false})
      {
        if (want_critical_only && !critical)
        {
          continue;
        }

        for (WorkerThreadPtr& worker : *waiting_worker_threads)
        {
          if (
            worker->critical_only == want_critical_only &&
            worker->assigned_task == nullptr)
          {
            worker->assigned_task = std::move(task);
            worker->cv.notify_one();
            return true;
          }
        }
      }
      return false;
    }

    // May run shutdown hooks, so callers must not hold board locks.
    void add_task(Task&& task) CCF_EXCLUDES(mutex, delayed.tasks_mutex)
    {
      const bool critical =
        task != nullptr && task->get_task_class() == TaskClass::Critical;
      ccf::ds::WorkBeaconPtr beacon;
      ccf::ds::WorkBeaconPtr critical_beacon;
      Task abandoned;
      {
        // Under lock
        ccf::ds::MutexGuard lock(mutex);
        if (!shut_down)
        {
          // First check if there is an idle worker waiting for a task
          if (assign_to_waiting_worker(task, critical))
          {
            return;
          }

          // There is no idle worker able to run this task, so enqueue it for
          // later execution. Wake external consumers only when a queue they
          // read becomes non-empty.
          if (no_pending_tasks())
          {
            beacon = work_beacon;
          }
          if (critical)
          {
            if (pending_critical_tasks.empty())
            {
              critical_beacon = critical_work_beacon;
            }
            pending_critical_tasks.emplace(std::move(task));
          }
          else
          {
            pending_tasks.emplace(std::move(task));
          }
        }
        else
        {
          abandoned = std::move(task);
        }
      }

      if (abandoned != nullptr)
      {
        abandoned->shutdown();
      }
      if (beacon != nullptr)
      {
        beacon->notify_work_available_coalesced();
      }
      if (critical_beacon != nullptr)
      {
        critical_beacon->notify_work_available_coalesced();
      }
    }

    Task get_task(bool critical_only = false)
    {
      using namespace std::chrono_literals;
      return wait_for_task(0ms, critical_only);
    }

    Task wait_for_task(
      const std::chrono::milliseconds& timeout, bool critical_only = false)
    {
      Task to_return = nullptr;

      {
        // Under lock
        ccf::ds::MutexGuard lock(mutex);

        // Get local copy to extend life, even if this object dies while we're
        // waiting.
        decltype(waiting_worker_threads) worker_threads =
          waiting_worker_threads;

        // Check if there are pending tasks this worker can execute, critical
        // tasks first
        if (!pending_critical_tasks.empty())
        {
          to_return = pending_critical_tasks.front();
          pending_critical_tasks.pop();
        }
        else if (!critical_only && !pending_tasks.empty())
        {
          to_return = pending_tasks.front();
          pending_tasks.pop();
        }
        else
        {
          if (stopping)
          {
            return nullptr;
          }

          // When no task is available, append this thread to
          // waiting_worker_threads and wait on a condition_variable
          WorkerThreadPtr waiting_worker =
            std::make_shared<WaitingWorkerThread>(to_return, critical_only);

          // Append local object to central collection
          worker_threads->push_back(waiting_worker);

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
            worker_threads->begin(), worker_threads->end(), waiting_worker);
          worker_threads->erase(it);
        }
      }

      return to_return;
    }

    void stop_waiters()
    {
      ccf::ds::MutexGuard lock(mutex);
      // Enclave shutdown is terminal, so future waits must not block either.
      stopping = true;
      for (const auto& worker : *waiting_worker_threads)
      {
        worker->cv.notify_one();
      }
    }

    // May run shutdown hooks, so callers must not hold board locks.
    void add_timed_task(
      Task task,
      std::chrono::milliseconds initial_delay,
      std::optional<std::chrono::milliseconds> periodic_delay)
      CCF_EXCLUDES(mutex, delayed.tasks_mutex)
    {
      {
        ccf::ds::MutexGuard lock(delayed.tasks_mutex);
        if (!delayed.shut_down)
        {
          const auto trigger_time = delayed.total_elapsed + initial_delay;
          delayed.tasks[trigger_time].emplace_back(
            std::move(task), periodic_delay);
          return;
        }
      }
      task->shutdown();
    }

    void tick(std::chrono::milliseconds elapsed)
      CCF_EXCLUDES(mutex, delayed.tasks_mutex)
    {
      std::vector<Task> ready_tasks;
      {
        ccf::ds::MutexGuard lock(delayed.tasks_mutex);
        elapsed += delayed.total_elapsed;
        delayed.total_elapsed = elapsed;

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

            ready_tasks.push_back(delayed_task.task);
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

      // Submit after releasing tasks_mutex, since add_task may run hooks
      for (auto& task : ready_tasks)
      {
        add_task(std::move(task));
      }
    }

    std::chrono::milliseconds get_current_time()
    {
      ccf::ds::MutexGuard lock(delayed.tasks_mutex);
      return delayed.total_elapsed;
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

  JobBoard::~JobBoard()
  {
    shutdown();
  }

  JobBoard::Registration::Registration(
    const std::shared_ptr<Registry>& registry_, BaseTask* task_) :
    registry(registry_),
    task(task_)
  {}

  JobBoard::Registration::~Registration()
  {
    if (auto live_registry = registry.lock())
    {
      ccf::ds::MutexGuard lock(live_registry->mutex);
      live_registry->tasks.erase(task);
    }
  }

  std::unique_ptr<JobBoard::Registration> JobBoard::register_task(
    const Task& task)
  {
    auto& registry = pimpl->registry;
    auto registration =
      std::unique_ptr<Registration>(new Registration(registry, task.get()));
    {
      ccf::ds::MutexGuard lock(registry->mutex);
      if (!registry->shut_down)
      {
        registry->tasks.emplace(task.get(), task);
        return registration;
      }
    }
    task->shutdown();
    return nullptr;
  }

  void JobBoard::shutdown()
  {
    std::queue<Task> pending;
    std::queue<Task> pending_critical;
    Delayed::DelayedTasksByTime delayed;
    decltype(Registry::tasks) registered;
    {
      ccf::ds::MutexGuard lock(pimpl->mutex);
      if (pimpl->shut_down)
      {
        return;
      }
      pimpl->shut_down = true;
      pimpl->stopping = true;
      pending.swap(pimpl->pending_tasks);
      pending_critical.swap(pimpl->pending_critical_tasks);
    }
    {
      ccf::ds::MutexGuard lock(pimpl->delayed.tasks_mutex);
      pimpl->delayed.shut_down = true;
      delayed.swap(pimpl->delayed.tasks);
    }
    {
      ccf::ds::MutexGuard lock(pimpl->registry->mutex);
      pimpl->registry->shut_down = true;
      registered.swap(pimpl->registry->tasks);
    }

    // No locks are held: releasing a capture may destroy a registered task,
    // cancel another task, or submit more work to this board.
    std::vector<Task> live_tasks;
    live_tasks.reserve(registered.size());
    for (const auto& [_, weak_task] : registered)
    {
      if (auto task = weak_task.lock())
      {
        live_tasks.push_back(std::move(task));
      }
    }
    for (const auto& task : live_tasks)
    {
      task->shutdown();
    }
    for (auto* queue : {&pending_critical, &pending})
    {
      while (!queue->empty())
      {
        queue->front()->shutdown();
        queue->pop();
      }
    }
    for (const auto& [_, tasks] : delayed)
    {
      for (const auto& entry : tasks)
      {
        entry.task->shutdown();
      }
    }
  }

  void JobBoard::set_work_beacon(ccf::ds::WorkBeaconPtr work_beacon)
  {
    pimpl->set_work_beacon(std::move(work_beacon));
  }

  void JobBoard::set_critical_work_beacon(ccf::ds::WorkBeaconPtr work_beacon)
  {
    pimpl->set_critical_work_beacon(std::move(work_beacon));
  }

  void JobBoard::add_task(Task task)
  {
    pimpl->add_task(std::move(task));
  }

  Task JobBoard::get_task()
  {
    return pimpl->get_task();
  }

  Task JobBoard::get_critical_task()
  {
    return pimpl->get_task(true);
  }

  Task JobBoard::wait_for_task(const std::chrono::milliseconds& timeout)
  {
    return pimpl->wait_for_task(timeout);
  }

  void JobBoard::stop_waiters()
  {
    pimpl->stop_waiters();
  }

  JobBoard::Summary JobBoard::get_summary()
  {
    Summary summary{};
    {
      ccf::ds::MutexGuard lock(pimpl->mutex);
      summary.pending_tasks =
        pimpl->pending_tasks.size() + pimpl->pending_critical_tasks.size();
      summary.idle_workers = pimpl->waiting_worker_threads->size();
    }
    {
      ccf::ds::MutexGuard lock(pimpl->registry->mutex);
      summary.registered_tasks = pimpl->registry->tasks.size();
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

  std::chrono::milliseconds JobBoard::get_current_time()
  {
    return pimpl->get_current_time();
  }

  void JobBoard::tick(std::chrono::milliseconds elapsed)
  {
    pimpl->tick(elapsed);
  }
}
