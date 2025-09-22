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
    std::string name;
    IJobBoard& job_board;

    std::mutex mutex;
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
      std::lock_guard<std::mutex> lock(pimpl->mutex);
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
      std::lock_guard<std::mutex> lock(pimpl->mutex);
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

  FanInTasks::FanInTasks(IJobBoard& jb, const std::string& s) :
    pimpl(std::make_unique<FanInTasks::PImpl>(s, jb))
  {}

  FanInTasks::~FanInTasks() = default;

  std::string_view FanInTasks::get_name() const
  {
    return pimpl->name;
  }

  void FanInTasks::add_task(size_t task_index, Task task)
  {
    {
      std::lock_guard<std::mutex> lock(pimpl->mutex);

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

  namespace
  {
    struct ConcreteFanInTasks : public FanInTasks
    {
    public:
      ConcreteFanInTasks(IJobBoard& jb, const std::string& s) :
        FanInTasks(jb, s)
      {}
    };
  }

  std::shared_ptr<FanInTasks> make_fan_in_tasks(
    IJobBoard& jb, const std::string& s)
  {
    return std::make_shared<ConcreteFanInTasks>(jb, s);
  }
}
