// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/basic_task.h"
#include "tasks/job_board.h"

#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace ccf::tasks
{
  class PeriodicTaskOwner
    : public std::enable_shared_from_this<PeriodicTaskOwner>
  {
    std::vector<Task> periodic_tasks;

  protected:
    using PeriodicFunction =
      std::function<void(std::chrono::milliseconds elapsed)>;

    void schedule_periodic_task(
      JobBoard& job_board,
      std::chrono::milliseconds period,
      PeriodicFunction function,
      std::string name)
    {
      auto weak_self = weak_from_this();
      if (weak_self.expired())
      {
        throw std::logic_error(
          "PeriodicTaskOwner must be shared before scheduling");
      }

      struct Timing
      {
        std::mutex lock;
        std::chrono::milliseconds last_run = {};
      };
      auto timing = std::make_shared<Timing>();
      timing->last_run = job_board.get_current_time();

      auto task = make_basic_task(
        [&job_board, weak_self, timing, function = std::move(function)]() {
          if (auto owner = weak_self.lock())
          {
            std::lock_guard<std::mutex> guard(timing->lock);
            const auto now = job_board.get_current_time();
            const auto elapsed = now - timing->last_run;
            timing->last_run = now;
            if (elapsed.count() > 0)
            {
              function(elapsed);
            }
          }
        },
        std::move(name));

      job_board.add_periodic_task(task, period, period);
      periodic_tasks.emplace_back(std::move(task));
    }

  public:
    virtual ~PeriodicTaskOwner()
    {
      for (auto& task : periodic_tasks)
      {
        task->cancel_task();
      }
    }
  };
}
