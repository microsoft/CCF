// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/uv/task.h"

#include <chrono>

namespace ccf::uv::tasks
{
  using TaskHandle = void*;

  class TaskSystem
  {
  public:
    static void init();

    static TaskHandle enqueue_task(
      std::unique_ptr<ccf::uv::tasks::Task>&& task);
    static TaskHandle enqueue_task_after_delay(
      std::unique_ptr<ccf::uv::tasks::Task>&& task,
      const std::chrono::milliseconds& delay);

    static bool cancel_task(TaskHandle&& token);

    static void run_for(const std::chrono::milliseconds& s);
  };
}