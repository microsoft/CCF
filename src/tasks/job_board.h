// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/work_beacon.h"
#include "tasks/job_board_interface.h"

#include <mutex>
#include <queue>

namespace ccf::tasks
{
  struct JobBoard : public IJobBoard
  {
    std::mutex mutex;
    std::queue<Task> queue;
    ccf::ds::WorkBeacon work_beacon;

    void add_task(Task&& t) override;
    Task get_task() override;
    bool empty() override;

    Task wait_for_task(const std::chrono::milliseconds& timeout) override;
  };
}
