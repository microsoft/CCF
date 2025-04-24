// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./node.h"

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

  std::function<std::string()> generate_next_action = []() {
    return std::string("TODO");
    // if (rand() % 4 == 0)
    // {
    //   return make_sleep_action(std::chrono::milliseconds(rand() % 5));
    // }
    // else
    // {
    //   TData d;
    //   for (auto& b : d)
    //   {
    //     b = rand();
    //   }
    //   return make_echo_action(
    //     d,
    //     rand() % 2 == 0 // half of actions are reverse
    //   );
    // }
  };
};

struct Client
{
  std::atomic<bool> stop_signal = false;
  std::thread thread;

  Client(Node::IO& io, const ClientParams& params)
  {
    using TClock = std::chrono::system_clock;

    thread = std::thread([&]() {
      const auto start = TClock::now();
      const auto submission_end = start + params.submission_duration;

      std::queue<std::string> pending_actions;

      while (!stop_signal)
      {
        // For some period of time...
        const bool still_submitting = TClock::now() < submission_end;
        if (still_submitting)
        {
          // ...generate and submit new work
          // TODO: Separate Action (a) from SerialisedAction
          auto a = params.generate_next_action();
          // std::cout << "Generated action " << a << std::endl;
          pending_actions.push(a);
          io.to_node.push_back(a);
        }

        // If we have any responses
        auto response = io.from_node.try_pop();
        while (response.has_value())
        {
          // Verify them (check that the first response matches the first
          // pending action)
          // TODO: REQUIRE(!pending_actions.empty());
          pending_actions.front().verify_response(response.value());
          pending_actions.pop();

          // ...and check for further responses
          response = io.from_node.try_pop();
        }

        // If we're finished submitting and have processed all responses...
        if (pending_actions.empty() && !still_submitting)
        {
          // ...then exit
          break;
        }
        else
        {
          // ...else pause and repeat
          params.submission_delay();
        }
      }
    });
  }

  ~Client()
  {
    stop_signal = true;
    thread.join();
  }
};
