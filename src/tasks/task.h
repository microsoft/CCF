// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/resumable.h"

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

  protected:
    virtual void do_task_implementation() = 0;

  public:
    virtual ~BaseTask() = default;

    void do_task();

    [[nodiscard]] virtual const std::string& get_name() const = 0;

    // A cancelled task is skipped by any worker which subsequently picks it
    // up. Tasks which queue further work of their own (eg, OrderedTasks)
    // override this to also release that work, since it will never be
    // executed: queued work commonly holds a reference back to the owner of
    // the task, and only executing or releasing it breaks that cycle.
    virtual void cancel_task();
    bool is_cancelled();
  };

  using Task = std::shared_ptr<BaseTask>;
}