// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./actions.h"
#include "./job_board.h"
#include "./looping_thread.h"
#include "./ordered_tasks.h"

struct Task_ProcessClientAction : public ITask
{
  const SerialisedAction input_action;
  Session& client_session;

  Task_ProcessClientAction(const SerialisedAction& action, Session& cs) :
    input_action(action),
    client_session(cs)
  {}

  size_t do_task()
  {
    // Separate into parse, exec, and respond tasks, to show it is
    // possible?
    auto received_action = deserialise_action(input_action);
    auto result = received_action->do_action();

    // TODO: Add some CallObligation type to ensure this is
    // eventually done?
    client_session.from_node.push_back(std::move(result));

    return 1;
  }

  std::string get_name() const
  {
    return fmt::format(
      "Processing action '{}' from session {}",
      input_action,
      (void*)&client_session);
  }
};

struct DispatcherState
{
  IJobBoard& job_board;
  SessionManager& session_manager;

  std::unordered_map<Session*, std::shared_ptr<OrderedTasks>>
    ordered_tasks_per_client;

  std::atomic<bool> consider_ternination = false;
};

struct Dispatcher : public LoopingThread<DispatcherState>
{
  Dispatcher(IJobBoard& jb, SessionManager& sm) :
    LoopingThread<DispatcherState>(fmt::format("dsp"), jb, sm)
  {}

  ~Dispatcher() override
  {
    shutdown();
  }

  Stage loop_behaviour() override
  {
    // Handle incoming IO, producing tasks to process each item
    // TODO: Ideally some kind of "session_manager.foreach", to avoid directly
    // taking their mutex?

    // Produce a return value of Terminated if consider_ternination has been
    // set, and we pop nothing off incoming in this iteration
    Stage ret_val =
      state.consider_ternination.load() ? Stage::Terminated : Stage::Running;

    std::lock_guard<std::mutex> lock(state.session_manager.sessions_mutex);
    for (auto& session : state.session_manager.all_sessions)
    {
      auto it = state.ordered_tasks_per_client.find(session.get());
      if (it == state.ordered_tasks_per_client.end())
      {
        it = state.ordered_tasks_per_client.emplace_hint(
          it,
          session.get(),
          std::make_shared<OrderedTasks>(
            state.job_board, fmt::format("Tasks for {}", session->name)));
      }

      auto& tasks = *it->second;

      auto incoming = session->to_node.try_pop();
      while (incoming.has_value())
      {
        ret_val = Stage::Running;

        tasks.add_task(std::make_shared<Task_ProcessClientAction>(
          incoming.value(), *session));

        incoming = session->to_node.try_pop();
      }
    }

    return ret_val;
  }
};
