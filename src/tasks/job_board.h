// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/work_beacon.h"
#include "tasks/task.h"

#include <optional>
#include <queue>

namespace ccf::tasks
{
  class JobBoard
  {
    struct PImpl;
    std::unique_ptr<PImpl> pimpl;
    struct Registry;

    void add_timed_task(
      Task task,
      std::chrono::milliseconds initial_delay,
      std::optional<std::chrono::milliseconds> periodic_delay);

  public:
    class Registration
    {
      friend class JobBoard;
      std::weak_ptr<Registry> registry;
      BaseTask* task;

      Registration(const std::shared_ptr<Registry>& registry_, BaseTask* task_);

    public:
      ~Registration();
      Registration(const Registration&) = delete;
      Registration& operator=(const Registration&) = delete;
    };

    JobBoard();
    ~JobBoard();

    // Weak registration discovers board-bound tasks even when paused/off-board.
    // Register each task once and keep the token for its lifetime; it
    // unregisters on destruction and remains safe to destroy after the board
    // itself.
    std::unique_ptr<Registration> register_task(const Task& task);

    // Call after all producers and workers have stopped, while task
    // dependencies are still alive. Discards ready, delayed and registered
    // tasks without executing them. Idempotent; also called by the destructor.
    // Cleanup may submit more work, which is shut down immediately rather than
    // queued.
    void shutdown();

    void set_work_beacon(ccf::ds::WorkBeaconPtr work_beacon);

    void add_task(Task t);
    Task get_task();

    Task wait_for_task(const std::chrono::milliseconds& timeout);
    void stop_waiters();

    struct Summary
    {
      size_t pending_tasks = {};
      size_t idle_workers = {};
      size_t registered_tasks = {};

      bool operator==(const Summary&) const = default;
    };
    Summary get_summary();

    void add_delayed_task(Task task, std::chrono::milliseconds delay);

    // A periodic task is enqueued at most once whenever deadlines are
    // observed, then rescheduled from that observation time. Missed periods
    // are not replayed.
    void add_periodic_task(
      Task task,
      std::chrono::milliseconds initial_delay,
      std::chrono::milliseconds repeat_period);

    std::chrono::milliseconds get_current_time();
    void tick(std::chrono::milliseconds elapsed);
  };
}
