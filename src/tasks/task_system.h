// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/task.h"

#include <chrono>

namespace ccf::tasks
{
  using TaskHandle = void*;

  class TaskSystem
  {
  public:
    static void init();

    static TaskHandle enqueue_task(std::unique_ptr<ccf::tasks::Task>&& task);
    static bool cancel_task(TaskHandle&& token);

    static void run_for(const std::chrono::milliseconds& s);
  };
}