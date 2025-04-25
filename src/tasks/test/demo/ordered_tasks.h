// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./job_board.h"
#include "ccf/ds/logger.h"

#include <mutex>

template <typename T>
class FunQueue
{
protected:
  std::mutex mutex;
  std::deque<T> queue;
  bool active;

  std::string describe_queue()
  {
    std::string s;
    for (auto& e : queue)
    {
      s += fmt::format("{}, ", e->get_name());
    }
    return s;
  }

public:
  bool push(T&& t)
  {
    std::lock_guard<std::mutex> lock(mutex);
    const bool ret = queue.empty() && !active;
    queue.emplace_back(std::forward<T>(t));
    LOG_DEBUG_FMT("After push, queue contains: {}", describe_queue());
    return ret;
  }

  using Visitor = std::function<void(T&&)>;
  bool pop_and_visit(Visitor&& visitor)
  {
    std::deque<T> local;
    {
      std::lock_guard<std::mutex> lock(mutex);
      // assert(!active);
      active = true;

      LOG_DEBUG_FMT("At start of pop, queue contains: {}", describe_queue());

      std::swap(local, queue);
    }

    for (auto&& entry : local)
    {
      visitor(std::forward<T>(entry));
    }

    {
      std::lock_guard<std::mutex> lock(mutex);
      // assert(active);
      active = false;

      LOG_DEBUG_FMT("At end of pop, queue contains: {}", describe_queue());

      return !queue.empty();
    }
  }
};

class OrderedTasks : public ITask, public std::enable_shared_from_this<ITask>
{
protected:
  std::string name;
  IJobBoard& job_board;
  FunQueue<Task> sub_tasks;

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
    LOG_DEBUG_FMT("Doing {}", get_name());
    if (sub_tasks.pop_and_visit([this](Task&& task) {
          LOG_DEBUG_FMT("Inside {}, doing {}", get_name(), task->get_name());
          task->do_task();
        }))
    {
      LOG_DEBUG_FMT(
        " queue was non-empty after popping, so enqueuing {}", get_name());
      enqueue_on_board();
    }
  }

  std::string get_name() const override
  {
    return name;
  }

  void add_task(Task&& task)
  {
    LOG_DEBUG_FMT("Adding task {} to {}", task->get_name(), get_name());
    if (sub_tasks.push(std::move(task)))
    {
      LOG_DEBUG_FMT(" queue was empty, so enqueuing {}", get_name());
      enqueue_on_board();
    }
  }
};