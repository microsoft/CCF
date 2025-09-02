// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/job_board.h"

#include <memory>
#include <mutex>

namespace ccf::tasks
{
  struct ITaskAction
  {
    virtual ~ITaskAction() = default;

    virtual void do_action() = 0;

    virtual std::string get_name() const
    {
      return "[Anon]";
    }
  };

  using TaskAction = std::shared_ptr<ITaskAction>;

  struct BasicTaskAction : public ITaskAction
  {
    using Fn = std::function<void()>;

    Fn fn;
    const std::string name;

    BasicTaskAction(const Fn& _fn, const std::string& s = "[Anon]") :
      fn(_fn),
      name(s)
    {}

    void do_action() override
    {
      fn();
    }

    std::string get_name() const override
    {
      return name;
    }
  };

  template <typename... Ts>
  TaskAction make_basic_action(Ts&&... ts)
  {
    return std::make_shared<BasicTaskAction>(std::forward<Ts>(ts)...);
  }

  // TODO: Juggle types here so that it's hard to make an OrderedTasks _not_
  // owned by a shared ptr
  // Self-scheduling collection of in-order tasks. Tasks
  // will be executed in the order they are added. To self-schedule, this
  // instance will ensure that it is posted to the given JobBoard whenever more
  // sub-tasks are available for execution.
  class OrderedTasks : public BaseTask,
                       public std::enable_shared_from_this<OrderedTasks>
  {
  protected:
    struct PImpl;
    std::unique_ptr<PImpl> pimpl = nullptr;

    struct ResumeOrderedTasks;

    void enqueue_on_board();

    // Constructor is protected, to ensure this is only created via the
    // make_ordered_tasks factory function (ensuring this is always owned by a
    // shared_ptr)
    OrderedTasks(IJobBoard& jb, const std::string& s);

  public:
    ~OrderedTasks();

    void do_task_implementation() override;
    ccf::tasks::Resumable pause() override;
    std::string get_name() const override;

    void add_action(TaskAction&& action);

    void get_queue_summary(size_t& num_pending, bool& is_active);
  };

  std::shared_ptr<OrderedTasks> make_ordered_tasks(
    IJobBoard& jb, const std::string& s = "[Ordered]");
}
