// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./actions.h"
#include "./looping_thread.h"
#include "tasks/job_board.h"
#include "tasks/ordered_tasks.h"
#include "tasks/task_system.h"

#include <future>

struct Action_ProcessClientAction : public ccf::tasks::ITaskAction
{
  const SerialisedAction input_action;
  Session& client_session;
  std::atomic<size_t>& responses_sent;

  Action_ProcessClientAction(
    const SerialisedAction& action, Session& cs, std::atomic<size_t>& rs) :
    input_action(action),
    client_session(cs),
    responses_sent(rs)
  {}

  void do_action() override
  {
    auto received_action = deserialise_action(input_action);
    auto result = received_action->do_action();

    if (rand() % 50 == 0)
    {
      auto paused_task = ccf::tasks::pause_current_task();

      // Rough hack to simulate "something async" happening
      auto _ = std::async(
        std::launch::async,
        [paused_task = std::move(paused_task),
         result = std::move(result),
         client_session = &client_session,
         responses_sent = &responses_sent]() mutable {
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
          client_session->from_node.push_back(std::move(result));
          ++responses_sent;
          ccf::tasks::resume_task(std::move(paused_task));
        });
    }
    else
    {
      client_session.from_node.push_back(std::move(result));
      ++responses_sent;
    }
  }

  std::string get_name() const override
  {
    return fmt::format(
      "Processing action '{}' from session {}",
      input_action,
      (void*)&client_session);
  }
};

struct DispatcherState
{
  ccf::tasks::IJobBoard& job_board;
  SessionManager& session_manager;
  std::atomic<size_t>& responses_sent;

  std::unordered_map<Session*, std::shared_ptr<ccf::tasks::OrderedTasks>>
    ordered_tasks_per_client;

  std::atomic<bool> consider_termination = false;
};

struct Dispatcher : public LoopingThread<DispatcherState>
{
  Dispatcher(
    ccf::tasks::IJobBoard& jb,
    SessionManager& sm,
    std::atomic<size_t>& response_count) :
    LoopingThread<DispatcherState>(fmt::format("dsp"), jb, sm, response_count)
  {}

  ~Dispatcher() override
  {
    shutdown();
  }

  Stage loop_behaviour() override
  {
    // Handle incoming IO, producing tasks to process each item

    // Produce a return value of Terminated if consider_termination has been
    // set, and we pop nothing off incoming in this iteration
    Stage ret_val =
      state.consider_termination.load() ? Stage::Terminated : Stage::Running;

    std::lock_guard<std::mutex> lock(state.session_manager.sessions_mutex);
    for (auto& session : state.session_manager.all_sessions)
    {
      auto it = state.ordered_tasks_per_client.find(session.get());
      if (it == state.ordered_tasks_per_client.end())
      {
        it = state.ordered_tasks_per_client.emplace_hint(
          it,
          session.get(),
          ccf::tasks::make_ordered_tasks(
            state.job_board, fmt::format("Tasks for {}", session->name)));
      }

      auto& tasks = *it->second;

      // If the client has abandoned this session, cancel all corresponding
      // tasks
      if (session->abandoned.load())
      {
        if (!tasks.is_cancelled())
        {
          tasks.cancel_task();
        }
      }
      else
      {
        // Otherwise, produce a task to process this client request
        auto incoming = session->to_node.try_pop();
        while (incoming.has_value())
        {
          ret_val = Stage::Running;

          tasks.add_action(std::make_shared<Action_ProcessClientAction>(
            incoming.value(), *session, state.responses_sent));

          incoming = session->to_node.try_pop();
        }
      }
    }

    return ret_val;
  }
};
