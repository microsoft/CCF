// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>

namespace ccf::tasks
{
  struct BaseTask;

  static thread_local BaseTask* current_task = nullptr;

  struct IResumable;
  void resume_task(std::unique_ptr<IResumable>&& resumable);

  struct IResumable
  {
  private:
    virtual void resume() = 0;

  public:
    virtual ~IResumable() = default;

    friend void ccf::tasks::resume_task(
      std::unique_ptr<IResumable>&& resumable);
  };

  using Resumable = std::unique_ptr<IResumable>;

  struct BaseTask
  {
    virtual ~BaseTask() = default;

    size_t do_task();

    virtual ccf::tasks::Resumable pause();

    // Return some value indicating how much work was done.
    virtual size_t do_task_implementation() = 0;

    virtual std::string get_name() const = 0;

    // Cancellation
    std::atomic<bool> cancelled = false;

    void cancel_task();

    bool is_cancelled();
  };

  using Task = std::shared_ptr<BaseTask>;

  Resumable pause_current_task();
  void resume_task(Resumable&& resumable);

  struct BasicTask : public BaseTask
  {
    using Fn = std::function<void()>;

    Fn fn;
    const std::string name;

    BasicTask(const Fn& _fn, const std::string& s = "[Anon]") : fn(_fn), name(s)
    {}

    size_t do_task_implementation() override
    {
      fn();
      return 1;
    }

    std::string get_name() const override
    {
      return name;
    }
  };

  template <typename T, typename... Ts>
  Task make_task(Ts&&... ts)
  {
    return std::make_shared<T>(std::forward<Ts>(ts)...);
  }

  template <typename... Ts>
  Task make_basic_task(Ts&&... ts)
  {
    return make_task<BasicTask>(std::forward<Ts>(ts)...);
  }
}