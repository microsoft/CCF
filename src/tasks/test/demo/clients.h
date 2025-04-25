// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./actions.h"
#include "./looping_thread.h"
#include "./session.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <queue>
#include <string>
#include <thread>

struct ClientParams
{
  std::chrono::milliseconds submission_duration =
    std::chrono::milliseconds(100);

  std::function<void()> submission_delay = []() { std::this_thread::yield(); };

  std::function<ActionPtr()> generate_next_action = []() {
    return std::make_unique<SignAction>();
  };
};

struct Client : public LoopingThread
{
  Session& session;
  const ClientParams& params;

  std::queue<ActionPtr> pending_actions;

  using TClock = std::chrono::system_clock;
  TClock::time_point submission_end;

  Client(Session& _session, const ClientParams& _params, size_t idx) :
    LoopingThread(fmt::format("c{}", idx)),
    session(_session),
    params(_params)
  {
    const auto start = TClock::now();
    this->submission_end = start + params.submission_duration;
  }

  bool loop_behaviour() override
  {
    const bool still_submitting = TClock::now() < submission_end;
    if (still_submitting)
    {
      // Generate and submit new work
      auto action = params.generate_next_action();
      session.to_node.emplace_back(action->serialise());
      pending_actions.push(std::move(action));
    }

    // If we have any responses
    auto response = session.from_node.try_pop();
    while (response.has_value())
    {
      // Verify them (check that the first response matches the first
      // pending action)
      REQUIRE(!pending_actions.empty());
      pending_actions.front()->verify_serialised_response(response.value());
      pending_actions.pop();

      // ...and check for further responses
      response = session.from_node.try_pop();
    }

    // End loop if this client has submitted and verified everything
    return pending_actions.empty() && !still_submitting;
  }

  bool idle_behaviour() override
  {
    params.submission_delay();
    return true;
  }
};
