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

  class SimpleTask : public Task
  {
  public:
    using ExecFn = std::function<void(void)>;
    using AfterFn = std::function<void(bool)>;

    SimpleTask(ExecFn&& exec_fn_, AfterFn&& after_fn_ = nullptr) :
      exec_fn(std::move(exec_fn_)),
      after_fn(std::move(after_fn_))
    {}

    void execute_task() override
    {
      exec_fn();
    }

    void after_task_cb(bool was_cancelled) override
    {
      if (after_fn != nullptr)
      {
        after_fn(was_cancelled);
      }
    }

  protected:
    ExecFn exec_fn;
    AfterFn after_fn;
  };
}