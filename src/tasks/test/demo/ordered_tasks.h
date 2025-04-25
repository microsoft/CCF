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
    std::mutex mutex;
    std::deque<Task> queue;
    bool active;

  public:
    bool push(T&& t)
    {
      std::lock_guard<std::mutex> lock(mutex);
      const bool ret = queue.empty() && !active;
      queue.emplace_back(std::forward<T>(t));
      return ret;
    }

    using Visitor = std::function<void(T&&)>;
    bool pop_and_visit(Visitor&& visitor)
    {
      decltype(queue) local;
      {
        std::lock_guard<std::mutex> lock(mutex);
        active = true;

        std::swap(local, queue);
      }

      for (auto&& entry : local)
      {
        visitor(std::forward<T>(entry));
      }

      {
        std::lock_guard<std::mutex> lock(mutex);
        active = false;
        return !queue.empty();
      }
    }
  };
}

// Self-scheduling collection of in-order tasks. Tasks will be executed in the
// order they are added. To self-schedule, this instance will ensure that it is
// posted to the given JobBoard whenever more sub-tasks are available for
// execution.
class OrderedTasks : public ITask, public std::enable_shared_from_this<ITask>
{
protected:
  std::string name;
  IJobBoard& job_board;
  SubTaskQueue<Task> sub_tasks;

  void enqueue_on_board()
  {
    job_board.add_task(shared_from_this());
  }

public:
  OrderedTasks(IJobBoard& jb, std::string_view sv = "[Ordered]") :
    job_board(jb),
    name(sv)
  {}

  void do_task() override
  {
    if (sub_tasks.pop_and_visit([this](Task&& task) { task->do_task(); }))
    {
      enqueue_on_board();
    }
  }

  std::string get_name() const override
  {
    return name;
  }

  void add_task(Task&& task)
  {
    if (sub_tasks.push(std::move(task)))
    {
      enqueue_on_board();
    }
  }
};