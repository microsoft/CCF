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

struct ClientState
{
  Session& session;
  const ClientParams& params;

  std::queue<ActionPtr> pending_actions;

  using TClock = std::chrono::system_clock;
  TClock::time_point submission_end;
};

struct Client : public LoopingThread<ClientState>
{
  Client(Session& _session, const ClientParams& _params, size_t idx) :
    LoopingThread<ClientState>(fmt::format("c{}", idx), _session, _params)
  {
    const auto start = State::TClock::now();
    state.submission_end = start + state.params.submission_duration;
  }

  bool loop_behaviour() override
  {
    const bool still_submitting = State::TClock::now() < state.submission_end;
    if (still_submitting)
    {
      // Generate and submit new work
      auto action = state.params.generate_next_action();
      state.session.to_node.emplace_back(action->serialise());
      state.pending_actions.push(std::move(action));
      LOG_INFO_FMT("Pushed a pending action");
    }

    // If we have any responses
    auto response = state.session.from_node.try_pop();
    while (response.has_value())
    {
      // Verify them (check that the first response matches the first
      // pending action)
      REQUIRE(!state.pending_actions.empty());
      state.pending_actions.front()->verify_serialised_response(
        response.value());
      state.pending_actions.pop();

      // ...and check for further responses
      response = state.session.from_node.try_pop();
    }

    // End loop if this client has submitted and verified everything
    const auto ret = state.pending_actions.empty() && !still_submitting;
    LOG_INFO_FMT("Returning {}", ret);
    return ret;
  }

  bool idle_behaviour() override
  {
    state.params.submission_delay();
    return true;
  }
};
