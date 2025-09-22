// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/job_board_interface.h"
#include "tasks/task.h"

#include <memory>

namespace ccf::tasks
{
  class FanInTasks : public BaseTask,
                     public std::enable_shared_from_this<FanInTasks>
  {
  protected:
    struct PImpl;
    std::unique_ptr<PImpl> pimpl = nullptr;

    void enqueue_on_board();
    void do_task_implementation() override;

    // Non-public constructor argument type, so this can only be constructed by
    // this class (ensuring shared ptr ownership)
    struct Private
    {
      explicit Private() = default;
    };

  public:
    FanInTasks(Private, IJobBoard& job_board_);
    ~FanInTasks();

    static std::shared_ptr<FanInTasks> create(IJobBoard& job_board_);

    const std::string& get_name() const override;

    void add_task(size_t task_index, Task task);
  };
}
