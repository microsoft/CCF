// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./locking_mpmc_queue.h"
#include "ds/internal_logger.h"

#include <atomic>
#include <string>
#include <vector>

struct Session
{
  const std::string name;

  ccf::tasks::LockingMPMCQueue<std::string> to_node;
  ccf::tasks::LockingMPMCQueue<std::string> from_node;

  std::atomic<bool> abandoned = false;

  Session(const std::string& s) : name(s) {}
};

struct SessionManager
{
  using SessionPtr = std::unique_ptr<Session>;

  ccf::pal::Mutex sessions_mutex;
  std::vector<SessionPtr> all_sessions CCF_GUARDED_BY(sessions_mutex);

  ~SessionManager()
  {
    LOG_DEBUG_FMT("Destroying SessionManager");
  }

  Session& new_session(const std::string& s)
  {
    ccf::pal::MutexGuard lock(sessions_mutex);
    return *all_sessions.emplace_back(std::make_unique<Session>(s));
  }
};