// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./locking_concurrent_queue.h"

#include <string>
#include <vector>

struct Session
{
  const std::string name;

  ccf::tasks::LockingConcurrentQueue<std::string> to_node;
  ccf::tasks::LockingConcurrentQueue<std::string> from_node;

  std::atomic<bool> abandoned = false;

  Session(const std::string& s) : name(s) {}
};

struct SessionManager
{
  using SessionPtr = std::unique_ptr<Session>;

  std::mutex sessions_mutex;
  std::vector<SessionPtr> all_sessions;

  ~SessionManager()
  {
    LOG_DEBUG_FMT("Destroying SessionManager");
  }

  Session& new_session(const std::string& s)
  {
    std::lock_guard<std::mutex> lock(sessions_mutex);
    return *all_sessions.emplace_back(std::make_unique<Session>(s));
  }
};