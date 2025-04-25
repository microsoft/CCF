// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./job_board.h"
#include "./looping_thread.h"
#include "./ordered_tasks.h"

struct Dispatcher : public LoopingThread
{
  IJobBoard& job_board;
  SessionManager& session_manager;

  std::unordered_map<Session*, std::shared_ptr<OrderedTasks>>
    ordered_tasks_per_client;

  Dispatcher(IJobBoard& jb, SessionManager& sm) :
    LoopingThread(fmt::format("dsp")),
    job_board(jb),
    session_manager(sm)
  {}

  bool loop_behaviour() override
  {
    // Handle incoming IO, producing tasks to process each item
    // TODO: Ideally some kind of "session_manager.foreach", to avoid directly
    // taking their mutex?
    std::lock_guard<std::mutex> lock(session_manager.sessions_mutex);
    for (auto& session : session_manager.all_sessions)
    {
      auto it = ordered_tasks_per_client.find(session.get());
      if (it == ordered_tasks_per_client.end())
      {
        it = ordered_tasks_per_client.emplace_hint(
          it,
          session.get(),
          std::make_shared<OrderedTasks>(
            job_board, fmt::format("Tasks for {}", session->name)));
      }

      auto& tasks = *it->second;

      auto incoming = session->to_node.try_pop();
      while (incoming.has_value())
      {
        auto [idx, remainder] = ccf::nonstd::split_1(incoming.value(), "|");
        auto task = make_task(
          [incoming = incoming, session = session.get()]() {
            // TODO: This is where the real work happens! Make it a custom
            // Task type to clarify?
            // Separate into parse, exec, and respond tasks, to show it is
            // possible?
            auto received_action = deserialise_action(incoming.value());
            auto result = received_action->do_action();

            // TODO: Add some CallObligation type to ensure this is
            // eventually done?
            session->from_node.push_back(std::move(result));
          },
          fmt::format("[do {}]", idx));
        tasks.add_task(std::move(task));

        incoming = session->to_node.try_pop();
      }
    }

    return false;
  }
};
