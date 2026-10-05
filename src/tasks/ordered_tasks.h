// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/job_board.h"

#include <memory>

namespace ccf::tasks
{
  struct ITaskAction
  {
    virtual ~ITaskAction() = default;

    virtual void do_action() = 0;

    // Only called for abandoned actions, never while executing. Implementations
    // must tolerate repeated notification if an action was queued more than
    // once.
    virtual void on_shutdown() noexcept {}

    [[nodiscard]] virtual const std::string& get_name() const = 0;
  };

  using TaskAction = std::shared_ptr<ITaskAction>;

  struct BasicTaskAction : public ITaskAction
  {
    using Fn = std::function<void()>;

    Fn fn;
    const std::string name;

    BasicTaskAction(Fn fn_, std::string name_ = "[Anon]") :
      fn(std::move(fn_)),
      name(std::move(name_))
    {}

    void do_action() override
    {
      fn();
    }

    void on_shutdown() noexcept override
    {
      fn = {};
    }

    [[nodiscard]] const std::string& get_name() const override
    {
      return name;
    }
  };

  template <typename... Ts>
  TaskAction make_basic_action(Ts&&... ts)
  {
    return std::make_shared<BasicTaskAction>(std::forward<Ts>(ts)...);
  }

  // Self-scheduling collection of in-order tasks. Tasks
  // will be executed in the order they are added. To self-schedule, this
  // instance will ensure that it is posted to the given JobBoard whenever more
  // sub-tasks are available for execution.
  class OrderedTasks : public BaseTask,
                       public std::enable_shared_from_this<OrderedTasks>
  {
  protected:
    struct PImpl;
    std::unique_ptr<PImpl> pimpl;

    struct ResumeOrderedTasks;

    void enqueue_on_board();
    void do_task_implementation() override;
    void on_shutdown() noexcept override;

    // Non-public constructor argument type, so this can only be constructed by
    // this class (ensuring shared ptr ownership)
    struct Private
    {
      explicit Private() = default;
    };

  public:
    OrderedTasks(
      Private force_private_constructor,
      JobBoard& job_board,
      const std::string& name);
    ~OrderedTasks() override;

    static std::shared_ptr<OrderedTasks> create(
      JobBoard& job_board_, const std::string& name_ = "[Ordered]");

    ccf::tasks::Resumable pause() override;
    const std::string& get_name() const override;

    void add_action(TaskAction&& action);

    void get_queue_summary(
      size_t& num_pending, bool& is_active, bool& is_paused);
  };
}
