// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/job_board.h"

#include <memory>

namespace ccf::tasks
{
  class ShiftSupervisor
  {
    struct PImpl;
    std::unique_ptr<PImpl> pimpl;

  public:
    ShiftSupervisor(JobBoard& job_board_);
    ~ShiftSupervisor();

    void set_worker_count(size_t new_worker_count);
  };
}