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
    std::chrono::milliseconds(1000);

  std::function<void()> submission_delay = []() {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  };

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

  size_t requests_sent;
  size_t responses_seen;
};

struct Client : public LoopingThread<ClientState>
{
  Client(Session& _session, const ClientParams& _params, size_t idx) :
    LoopingThread<ClientState>(fmt::format("c{}", idx), _session, _params)
  {}

  ~Client() override
  {
    shutdown();

    LOG_INFO_FMT(
      "Shutting down {}, sent {} requests and saw {} responses",
      name,
      state.requests_sent,
      state.responses_seen);
    REQUIRE(state.requests_sent == state.responses_seen);
  }

  void init_behaviour() override
  {
    const auto start = State::TClock::now();
    state.submission_end = start + state.params.submission_duration;
  }

  Stage loop_behaviour() override
  {
    const bool still_submitting = State::TClock::now() < state.submission_end;
    if (still_submitting)
    {
      // Generate and submit new work
      auto action = state.params.generate_next_action();
      state.session.to_node.emplace_back(action->serialise());
      state.pending_actions.push(std::move(action));
      ++state.requests_sent;
      LOG_DEBUG_FMT("Pushed a pending action");
    }

    // If we have any responses
    auto response = state.session.from_node.try_pop();
    while (response.has_value())
    {
      // Verification is expensive, so we end up spending a long tail time in
      // this test verifying every response (longer than we spent doing real
      // work). Mitigate this by only checking some responses, randomly
      // determined, estimating how far 'behind' we are (and thus how likely we
      // should be to skip verification) by the length of pending messages.
      const auto n = rand() % 100;
      if (n >= state.pending_actions.size() || n == 0)
      {
        // Verify (check that the first response matches the first pending
        // action)
        REQUIRE(!state.pending_actions.empty());
        state.pending_actions.front()->verify_serialised_response(
          response.value());
      }

      state.pending_actions.pop();
      ++state.responses_seen;

      // ...and check for further responses
      response = state.session.from_node.try_pop();
    }

    // End loop if this client has submitted and verified everything
    if (still_submitting)
    {
      return Stage::Running;
    }
    else
    {
      if (state.pending_actions.empty())
      {
        return Stage::Terminated;
      }
      else
      {
        return Stage::ShuttingDown;
      }
    }
  }

  Stage idle_behaviour() override
  {
    state.params.submission_delay();
    return lifetime_stage.load();
  }
};
