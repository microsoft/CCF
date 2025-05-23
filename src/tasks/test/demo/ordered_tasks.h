// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./job_board.h"
#include "ccf/ds/logger.h"

#include <mutex>

namespace
{
  // Helper type for OrderedTasks, containing a list of sub-tasks to be
  // performed in-order. Modifiers return bools indicating whether the caller is
  // responsible for scheduling a future flush of this queue.
  template <typename T>
  class SubTaskQueue
  {
  protected:
  public: // TODO: Bit weird
    std::mutex mutex;
    std::deque<T> queue;
    std::atomic<bool> active;
    std::atomic<bool> paused;

  public:
    bool push(T&& t)
    {
      std::lock_guard<std::mutex> lock(mutex);
      const bool ret = queue.empty() && !active.load();
      queue.emplace_back(std::forward<T>(t));
      return ret;
    }

    using Visitor = std::function<void(T&&)>;
    bool pop_and_visit(Visitor&& visitor)
    {
      decltype(queue) local;
      {
        std::lock_guard<std::mutex> lock(mutex);
        active.store(true);

        std::swap(local, queue);
      }

      for (auto&& entry : local)
      {
        visitor(std::forward<T>(entry));
      }

      {
        std::lock_guard<std::mutex> lock(mutex);
        active.store(false);
        return !queue.empty() && !paused.load();
      }
    }

    void pause()
    {
      std::lock_guard<std::mutex> lock(mutex);
      paused.store(true);
    }

    bool unpause()
    {
      std::lock_guard<std::mutex> lock(mutex);
      paused.store(false);
      return !queue.empty() && !active.load();
    }
  };

  struct ITaskAction
  {
    // Return some value indicating how much work was done.
    virtual size_t do_action() = 0;

    virtual std::string get_name() const = 0;
  };

  using TaskAction = std::shared_ptr<ITaskAction>;
}

// Self-scheduling collection of in-order tasks. Tasks will be executed in the
// order they are added. To self-schedule, this instance will ensure that it is
// posted to the given JobBoard whenever more sub-tasks are available for
// execution.
class OrderedTasks : public ITask,
                     public std::enable_shared_from_this<OrderedTasks>
{
protected:
public: // TODO: Bit weird
  std::string name;
  IJobBoard& job_board;
  SubTaskQueue<TaskAction> actions;

  void enqueue_on_board()
  {
    job_board.add_task(shared_from_this());
  }

public:
  OrderedTasks(IJobBoard& jb, const std::string& s = "[Ordered]") :
    job_board(jb),
    name(s)
  {}

  size_t do_task_implementation() override
  {
    size_t n = 0;
    if (actions.pop_and_visit(
          [this, &n](TaskAction&& action) { n += action->do_action(); }))
    {
      enqueue_on_board();
    }
    return n;
  }

  struct ResumeOrderedTasks : public ccf::tasks::IResumable
  {
    std::shared_ptr<OrderedTasks> tasks;

    ResumeOrderedTasks(std::shared_ptr<OrderedTasks> t) : tasks(t) {}

    void resume() override
    {
      if (tasks->actions.unpause())
      {
        tasks->enqueue_on_board();
      }
    }
  };

  ccf::tasks::Resumable pause() override
  {
    actions.pause();

    return std::make_unique<ResumeOrderedTasks>(shared_from_this());
  }

  std::string get_name() const override
  {
    return name;
  }

  void add_action(TaskAction&& action)
  {
    if (actions.push(std::move(action)))
    {
      enqueue_on_board();
    }
  }
};