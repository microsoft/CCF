// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/task.h"

#include <mutex>
#include <queue>
#include <thread>

namespace ccf::tasks
{
  struct IJobBoard
  {
    virtual void add_task(Task&& t) = 0;
    virtual Task get_task() = 0;
    virtual bool empty() = 0;

    virtual Task wait_for_task(const std::chrono::milliseconds& timeout) = 0;
  };
}
