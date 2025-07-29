// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./actions.h"
#include "./dispatcher.h"
#include "./session.h"
#include "./worker.h"
#include "tasks/job_board.h"
#include "tasks/ordered_tasks.h"

#include <atomic>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

struct Node
{
  SessionManager session_manager;

  ccf::tasks::IJobBoard& job_board;

  Dispatcher dispatcher;
  std::vector<std::unique_ptr<Worker>> workers;

  Node(size_t num_workers, ccf::tasks::IJobBoard& jb) :
    job_board(jb),
    dispatcher(jb, session_manager)
  {
    for (size_t i = 0; i < num_workers; ++i)
    {
      workers.push_back(std::make_unique<Worker>(job_board, i));
    }
  }

  void start()
  {
    dispatcher.start();
    for (auto& worker : workers)
    {
      worker->start();
    }
  }

  Session& new_session(const std::string& s)
  {
    return session_manager.new_session(s);
  }
};