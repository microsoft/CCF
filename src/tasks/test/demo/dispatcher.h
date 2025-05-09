// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./actions.h"
#include "./cancellable_task.h"
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
    /*
    Something like this?
    What are the nested ordering semantics here?
    Is this actually required, or only the deferral step?

    What if the state management and splitting was the responsibility of the
    dispatcher? So they create some bit of shared state for the eventual
    "Result", and enqueue first a Process and then a Respond task referring to
    this? Then the Process task's requirement is to populate this state, but it
    _may_ do so asynchronously (by deferring itself, and only rescheduling in
    some lambda that also populate the shared state).
    This is not so flexible (task dependencies need to be known in advance), but
    may be sufficient?

    Technically we could have 2 task queues here, for processing and requests
    (you can process A, B, and C before responding to A. But you can't respond
    to B before responding to A). But this just leaves a weird hole where you've
    "processed" something, but never get around to responding. Responding
    immediately after processing is not a critical dependency, but helpful
    expectation in-practice?

    Tasks::current_task()
      .then(
        () { return deserialise_action(input_action); }
      )
      .then(
        (ActionPtr&& action) {
          if (immediate) return action->do_action();
          else
          {
            auto deferral = Tasks::defer_self();
            Tasks::schedule(
              sleep_for_a_while_and_then_reschedule(deferral)
            );
          }
        }
      )
      .then(
        (SerialisedResponse&& result) {
          client_session.from_node.push_back(std::move(result));
        }
      )

    */
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

  std::unordered_map<Session*, std::shared_ptr<Cancellable<OrderedTasks>>>
    ordered_tasks_per_client;

  std::atomic<bool> consider_termination = false;
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
          make_cancellable_task<OrderedTasks>(
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

          tasks.add_task(std::make_shared<Task_ProcessClientAction>(
            incoming.value(), *session));

          incoming = session->to_node.try_pop();
        }
      }
    }

    return ret_val;
  }
};
