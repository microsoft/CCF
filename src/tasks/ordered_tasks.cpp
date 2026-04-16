// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/ordered_tasks.h"

#include "tasks/sub_task_queue.h"

#include <atomic>

namespace ccf::tasks
{
  struct OrderedTasks::PImpl
  {
    JobBoard& job_board;
    const std::string name;
    SubTaskQueue<TaskAction> actions;

    // Guard against multiple concurrent enqueue_on_board() calls.
    // Only the caller that flips this from false->true actually enqueues.
    // Cleared when do_task_implementation decides not to re-enqueue.
    std::atomic<bool> board_enqueued{false};
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
    // Only the caller that flips false->true actually enqueues. This prevents
    // double-enqueue when push() and unpause() both return true from different
    // threads before either has a chance to call add_task().
    if (!pimpl->board_enqueued.exchange(true))
    {
      pimpl->job_board.add_task(shared_from_this());
    }
  }

  OrderedTasks::~OrderedTasks() = default;

  OrderedTasks::OrderedTasks(
    [[maybe_unused]] OrderedTasks::Private force_private_constructor,
    JobBoard& job_board_,
    const std::string& name) :
    pimpl(std::make_unique<OrderedTasks::PImpl>(job_board_, name))
  {}

  void OrderedTasks::do_task_implementation()
  {
    if (pimpl->actions.pop_and_visit(
          [](TaskAction&& action) { action->do_action(); }))
    {
      // More work to do - stay on the board (flag remains true)
      pimpl->job_board.add_task(shared_from_this());
    }
    else
    {
      // No more work right now. Clear the flag so future push()/unpause()
      // callers can re-enqueue us.
      pimpl->board_enqueued.store(false);

      // Edge case: a push() or unpause() may have occurred between
      // pop_and_visit returning false and our store(false) above.
      // That caller would have seen board_enqueued==true and skipped
      // the enqueue, so we must check and re-enqueue if needed.
      // Skip re-enqueue while paused - unpause() will handle it.
      size_t num_pending = 0;
      bool is_active = false;
      bool is_paused = false;
      pimpl->actions.get_queue_summary(num_pending, is_active, is_paused);
      if (num_pending > 0 && !is_active && !is_paused)
      {
        enqueue_on_board();
      }
    }
  }

  ccf::tasks::Resumable OrderedTasks::pause()
  {
    pimpl->actions.pause();

    return std::make_unique<ResumeOrderedTasks>(shared_from_this());
  }

  const std::string& OrderedTasks::get_name() const
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

  void OrderedTasks::get_queue_summary(
    size_t& num_pending, bool& is_active, bool& is_paused)
  {
    pimpl->actions.get_queue_summary(num_pending, is_active, is_paused);
  }

  std::shared_ptr<OrderedTasks> OrderedTasks::create(
    JobBoard& job_board_, const std::string& name)
  {
    return std::make_shared<OrderedTasks>(Private{}, job_board_, name);
  }
}
