// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <deque>
#include <functional>
#include <memory>

namespace ccf::tasks
{
  class Task
  {
  public:
    virtual ~Task() = default;
    virtual void execute_task() = 0;
    virtual void after_task_cb(bool was_cancelled) {}
  };
}