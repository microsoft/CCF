// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/ordered_tasks.h"

#include "tasks/sub_task_queue.h"

namespace ccf::tasks
{
  struct OrderedTasks::PImpl
  {
    std::string name;
    IJobBoard& job_board;
    SubTaskQueue<TaskAction> actions;
  };

  struct OrderedTasks::ResumeOrderedTasks : public ccf::tasks::IResumable
  {
    std::shared_ptr<OrderedTasks> tasks;

    ResumeOrderedTasks(std::shared_ptr<OrderedTasks> tasks_) :
      tasks(std::move(tasks_))
    {}

    void resume() override
    {
      if (tasks->pimpl->actions.unpause())
      {
        tasks->enqueue_on_board();
      }
    }
  };

  void OrderedTasks::enqueue_on_board()
  {
    pimpl->job_board.add_task(shared_from_this());
  }

  OrderedTasks::~OrderedTasks() = default;

  OrderedTasks::OrderedTasks(
    [[maybe_unused]] OrderedTasks::Private force_private_constructor,
    IJobBoard& job_board_,
    const std::string& name_) :
    pimpl(std::make_unique<OrderedTasks::PImpl>(name_, job_board_))
  {}

  void OrderedTasks::do_task_implementation()
  {
    if (pimpl->actions.pop_and_visit(
          [this](TaskAction&& action) { action->do_action(); }))
    {
      enqueue_on_board();
    }
  }

  ccf::tasks::Resumable OrderedTasks::pause()
  {
    pimpl->actions.pause();

    return std::make_unique<ResumeOrderedTasks>(shared_from_this());
  }

  std::string_view OrderedTasks::get_name() const
  {
    return pimpl->name;
  }

  void OrderedTasks::add_action(TaskAction&& action)
  {
    if (pimpl->actions.push(std::move(action)))
    {
      enqueue_on_board();
    }
  }

  void OrderedTasks::get_queue_summary(size_t& num_pending, bool& is_active)
  {
    pimpl->actions.get_queue_summary(num_pending, is_active);
  }

  std::shared_ptr<OrderedTasks> OrderedTasks::create(
    IJobBoard& job_board_, const std::string& name_)
  {
    return std::make_shared<OrderedTasks>(Private{}, job_board_, name_);
  }
}
