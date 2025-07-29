// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>

struct ITask;

namespace ccf::tasks
{
  static thread_local ITask* current_task = nullptr;

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
}

struct ITask
{
  virtual ~ITask() = default;

  size_t do_task()
  {
    if (cancelled.load())
    {
      return 0;
    }

    ccf::tasks::current_task = this;

    const auto n = do_task_implementation();

    ccf::tasks::current_task = nullptr;

    return n;
  }

  virtual ccf::tasks::Resumable pause()
  {
    return nullptr;
  }

  // Return some value indicating how much work was done.
  virtual size_t do_task_implementation() = 0;

  virtual std::string get_name() const = 0;

  // Cancellation
  std::atomic<bool> cancelled = false;

  void cancel_task()
  {
    cancelled.store(true);
  }

  bool is_cancelled()
  {
    return cancelled.load();
  }
};

using Task = std::shared_ptr<ITask>;

namespace ccf::tasks
{
  Resumable pause_current_task()
  {
    if (current_task == nullptr)
    {
      throw std::logic_error("Cannot pause: No task currently running");
    }

    auto handle = current_task->pause();
    if (handle == nullptr)
    {
      throw std::logic_error("Cannot pause: Current task is not pausable");
    }

    return handle;
  }

  void resume_task(Resumable&& resumable)
  {
    resumable->resume();
  }
}

struct BasicTask : public ITask
{
  using Fn = std::function<void()>;

  Fn fn;
  const std::string name;

  BasicTask(const Fn& _fn, const std::string& s = "[Anon]") : name(s), fn(_fn)
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
