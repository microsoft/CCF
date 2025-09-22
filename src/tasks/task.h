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

    virtual std::string_view get_name() const
    {
      return "[Anon]";
    }

    void cancel_task();
    bool is_cancelled();
  };

  using Task = std::shared_ptr<BaseTask>;
}