// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/task_system.h"

#include <atomic>
#include <chrono>
#include <thread>

namespace ccf::tasks::test
{
  struct TaskSystemThread
  {
    std::chrono::milliseconds polling_period;
    std::thread thread;
    std::atomic<bool> terminate = false;

    TaskSystemThread(
      std::chrono::milliseconds _polling_period =
        std::chrono::milliseconds(10)) :
      polling_period(_polling_period)
    {
      thread = std::thread([this]() {
        while (!this->terminate.load())
        {
          ccf::tasks::tick(this->polling_period);

          auto& job_board = ccf::tasks::get_main_job_board();
          auto task = job_board.get_task();
          while (task != nullptr)
          {
            task->do_task();
            task = job_board.get_task();
          }

          std::this_thread::sleep_for(this->polling_period);
        }
      });
    }

    ~TaskSystemThread()
    {
      terminate.store(true);
      thread.join();
    }
  };
}
