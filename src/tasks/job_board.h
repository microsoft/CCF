// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/work_beacon.h"
#include "tasks/task.h"

#include <mutex>
#include <optional>
#include <queue>

namespace ccf::tasks
{
  class JobBoard
  {
    struct PImpl;
    std::unique_ptr<PImpl> pimpl = nullptr;

    void add_timed_task(
      Task task,
      std::chrono::milliseconds initial_delay,
      std::optional<std::chrono::milliseconds> periodic_delay);

  public:
    JobBoard();
    ~JobBoard();

    void add_task(Task t);
    Task get_task();

    Task wait_for_task(const std::chrono::milliseconds& timeout);

    struct Summary
    {
      size_t pending_tasks;

      size_t idle_workers;

      bool operator==(const Summary&) const = default;
    };
    Summary get_summary();

    void add_delayed_task(Task task, std::chrono::milliseconds delay);
    void add_periodic_task(
      Task task,
      std::chrono::milliseconds initial_delay,
      std::chrono::milliseconds repeat_period);
    void tick(std::chrono::milliseconds elapsed);
  };
}
