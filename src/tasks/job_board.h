// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/work_beacon.h"
#include "tasks/task.h"

#include <mutex>
#include <queue>

namespace ccf::tasks
{
  struct JobBoard
  {
    struct PImpl;
    std::unique_ptr<PImpl> pimpl = nullptr;

    JobBoard();
    ~JobBoard();

    void add_task(Task&& t);
    Task get_task();

    struct Summary
    {
      size_t pending_tasks;
      size_t idle_workers;

      bool operator==(const Summary&) const = default;
    };
    Summary get_summary();

    Task wait_for_task(const std::chrono::milliseconds& timeout);
  };
}
