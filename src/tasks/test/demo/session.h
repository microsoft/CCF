// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/types/locking_concurrent_queue.h"

#include <string>
#include <vector>

struct Session
{
  const std::string name;

  ccf::tasks::LockingConcurrentQueue<std::string> to_node;
  ccf::tasks::LockingConcurrentQueue<std::string> from_node;

  Session(std::string_view sv) : name(sv) {}
};

struct SessionManager
{
  using SessionPtr = std::unique_ptr<Session>;

  std::mutex sessions_mutex;
  std::vector<SessionPtr> all_sessions;

  Session& new_session(std::string_view sv)
  {
    std::lock_guard<std::mutex> lock(sessions_mutex);
    return *all_sessions.emplace_back(std::make_unique<Session>(sv));
  }
};