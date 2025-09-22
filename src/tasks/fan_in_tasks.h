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

    // Constructor is protected, to ensure this is only created via the
    // make_fan_in_tasks factory function (ensuring this is always owned by
    // a shared_ptr)
    FanInTasks(IJobBoard& job_board_, const std::string& name_);

  public:
    ~FanInTasks();

    std::string_view get_name() const override;

    void add_task(size_t task_index, Task task);
  };

  std::shared_ptr<FanInTasks> make_fan_in_tasks(
    IJobBoard& job_board_, const std::string& name_ = "[FanIn]");
}
