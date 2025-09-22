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
    bool empty();

    Task wait_for_task(const std::chrono::milliseconds& timeout);
  };
}
