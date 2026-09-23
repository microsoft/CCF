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
    std::atomic<bool> shut_down = false;

    friend Resumable ccf::tasks::pause_current_task();
    virtual ccf::tasks::Resumable pause();

  protected:
    virtual void do_task_implementation() = 0;
    virtual void on_shutdown() noexcept {}

  public:
    virtual ~BaseTask() = default;

    void do_task();

    [[nodiscard]] virtual const std::string& get_name() const = 0;

    void cancel_task();
    bool is_cancelled();

    // Terminal resource release, unlike cancellation. Call only once task
    // execution and producers have stopped. on_shutdown() runs exactly once,
    // even if shutdown() is re-entered or called concurrently.
    void shutdown() noexcept;
    [[nodiscard]] bool is_shutdown() const;
  };

  using Task = std::shared_ptr<BaseTask>;
}