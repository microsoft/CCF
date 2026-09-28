// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/resumable.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace ccf::tasks
{
  // Critical tasks are latency-sensitive and must not block. Every worker
  // prefers them, and reserved executors run only them, so opaque or
  // blocking general tasks cannot exhaust the capacity they need.
  enum class TaskClass : uint8_t
  {
    General,
    Critical
  };

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

    [[nodiscard]] virtual TaskClass get_task_class() const
    {
      return TaskClass::General;
    }

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