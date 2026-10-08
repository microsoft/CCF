// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/job_board.h"
#include "tasks/task.h"

#include <chrono>
#include <memory>
#include <string>

namespace ccf
{
  template <typename Node>
  class RecoveredServiceOpeningTask
    : public tasks::BaseTask,
      public std::enable_shared_from_this<RecoveredServiceOpeningTask<Node>>
  {
    std::weak_ptr<Node> node;
    tasks::JobBoard& board;
    const std::chrono::milliseconds retry_interval;
    const std::string name = "Recovered service opening";

    void do_task_implementation() override
    {
      if (auto owner = node.lock())
      {
        if (owner->open_recovered_service_if_primary())
        {
          // Schedule only after this attempt finishes: there is never an
          // overlapping retry or a permanent periodic registration.
          board.add_delayed_task(this->shared_from_this(), retry_interval);
        }
      }
    }

  public:
    RecoveredServiceOpeningTask(
      const std::shared_ptr<Node>& node_,
      tasks::JobBoard& board_,
      std::chrono::milliseconds retry_interval_) :
      node(node_),
      board(board_),
      retry_interval(retry_interval_)
    {}

    [[nodiscard]] const std::string& get_name() const override
    {
      return name;
    }
  };
}
