// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/fan_in_tasks.h"

#include <map>
#include <mutex>
#include <stdexcept>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ccf::tasks
{
  struct FanInTasks::PImpl
  {
    IJobBoard& job_board;

    // Synchronise access to pending_tasks and next_expected_task_index
    std::mutex pending_tasks_mutex;
    std::map<size_t, Task> pending_tasks;
    size_t next_expected_task_index = 0;

    std::atomic<bool> active = false;
  };

  void FanInTasks::enqueue_on_board()
  {
    pimpl->job_board.add_task(shared_from_this());
  }

  void FanInTasks::do_task_implementation()
  {
    std::vector<Task> current_batch;

    {
      std::lock_guard<std::mutex> lock(pimpl->pending_tasks_mutex);
      pimpl->active.store(true);

      auto it = pimpl->pending_tasks.find(pimpl->next_expected_task_index);
      while (it != pimpl->pending_tasks.end())
      {
        current_batch.push_back(it->second);
        pimpl->pending_tasks.erase(it);

        ++pimpl->next_expected_task_index;
        it = pimpl->pending_tasks.find(pimpl->next_expected_task_index);
      }
    }

    for (auto& task : current_batch)
    {
      task->do_task();
    }

    {
      std::lock_guard<std::mutex> lock(pimpl->pending_tasks_mutex);
      pimpl->active.store(false);

      auto it = pimpl->pending_tasks.find(pimpl->next_expected_task_index);
      if (it != pimpl->pending_tasks.end())
      {
        // While we were executing the previous batch, a call to fan_in_task
        // provided the _next_ contiguous task. We're now responsible for
        // re-enqueuing this task
        enqueue_on_board();
      }
    }
  }

  FanInTasks::FanInTasks(
    [[maybe_unused]] FanInTasks::Private force_private_constructor,
    IJobBoard& job_board_) :
    pimpl(std::make_unique<FanInTasks::PImpl>(job_board_))
  {}

  FanInTasks::~FanInTasks() = default;

  const std::string& FanInTasks::get_name() const
  {
    static const std::string name = "FanInTasks";
    return name;
  }

  void FanInTasks::add_task(size_t task_index, Task task)
  {
    {
      std::lock_guard<std::mutex> lock(pimpl->pending_tasks_mutex);

      if (task_index < pimpl->next_expected_task_index)
      {
        throw std::runtime_error(fmt::format(
          "[{}] Received task {} ({}) out-of-order - already advanced next "
          "expected "
          "to {}",
          get_name(),
          task_index,
          task->get_name(),
          pimpl->next_expected_task_index));
      }

      auto it = pimpl->pending_tasks.find(task_index);
      if (it != pimpl->pending_tasks.end())
      {
        throw std::runtime_error(fmt::format(
          "[{}] Received duplicate task {} ({}) - already have pending task {}",
          get_name(),
          task_index,
          task->get_name(),
          it->second == nullptr ? std::string("nullptr") :
                                  it->second->get_name()));
      }

      pimpl->pending_tasks.emplace(task_index, task);

      if (!pimpl->active.load())
      {
        if (task_index == pimpl->next_expected_task_index)
        {
          enqueue_on_board();
        }
      }
    }
  }

  std::shared_ptr<FanInTasks> FanInTasks::create(IJobBoard& job_board_)
  {
    return std::make_shared<FanInTasks>(Private{}, job_board_);
  }
}
