// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/task_system.h"

#include <atomic>
#include <functional>
#include <memory>
#include <string>

namespace ccf::tasks
{
  struct BaseTask
  {
  private:
    std::atomic<bool> cancelled = false;

    friend Resumable ccf::tasks::pause_current_task();
    virtual ccf::tasks::Resumable pause();

  public:
    virtual ~BaseTask() = default;

    void do_task();

    virtual void do_task_implementation() = 0;
    virtual std::string get_name() const = 0;

    void cancel_task();
    bool is_cancelled();
  };

  using Task = std::shared_ptr<BaseTask>;

  template <typename T, typename... Ts>
  Task make_task(Ts&&... ts)
  {
    return std::make_shared<T>(std::forward<Ts>(ts)...);
  }
}