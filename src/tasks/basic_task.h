// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/task.h"

namespace ccf::tasks
{
  struct BasicTask : public BaseTask
  {
    using Fn = std::function<void()>;

    Fn fn;
    const std::string name;

    BasicTask(const Fn& _fn, const std::string& s = "[Anon]") : fn(_fn), name(s)
    {}

    void do_task_implementation() override
    {
      fn();
    }

    std::string get_name() const override
    {
      return name;
    }
  };

  template <typename... Ts>
  Task make_basic_task(Ts&&... ts)
  {
    return std::make_shared<BasicTask>(std::forward<Ts>(ts)...);
  }
}