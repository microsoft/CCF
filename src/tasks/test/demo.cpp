// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "./demo/locking_concurrent_queue.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <doctest/doctest.h>
#include <functional>
#include <iostream>
#include <queue>
#include <string>
#include <thread>

// Trying to demonstrate a mock of the real flows (kinds of tasks, dependencies
// between them) we need to support

static constexpr size_t NUM_CLIENTS = 3;
static constexpr size_t NUM_WORKERS = 1;

using TClock = std::chrono::system_clock;

using TData = uint8_t[20];

std::atomic<size_t> id_generator = 0;

struct Action
{
  size_t id = ++id_generator;

  enum class Kind
  {
    Sleep, // TODO: Replace this with some crypto. Want to simulate expensive
           // _blocking_ work, sleep could be done non-blocking
    Echo,
    // TODO: Add some kind of "WaitUntil" Action, triggered by something else?
    // TODO: Add something explicitly going async?
  } kind;

  union
  {
    struct
    {
      std::chrono::milliseconds duration;
    } sleep;

    struct
    {
      TData original = {0};
      bool reverse = false;
    } echo = {0};
  } args;
};

Action make_sleep_action(const std::chrono::milliseconds& duration)
{
  Action action;
  action.kind = Action::Kind::Sleep;
  action.args.sleep.duration = duration;
  return action;
}

Action make_echo_action(const TData& data, bool reverse = false)
{
  Action action;
  action.kind = Action::Kind::Echo;
  std::memcpy(action.args.echo.original, data, sizeof(data));
  action.args.echo.reverse = reverse;
  return action;
}

struct Response
{
  size_t id;
  Action::Kind kind;

  union
  {
    struct
    {
      TClock::time_point started;
      TClock::time_point ended;
    } sleep;

    struct
    {
      TData value = {0};
    } echo = {0};
  } result;
};

using ResponseHandler = std::function<void(Response&&)>;

void server_enact(const Action& action, const ResponseHandler& handle_response)
{
  Response response;
  response.id = action.id;
  response.kind = action.kind;

  std::cout << "Doing action " << action.id << std::endl;

  switch (action.kind)
  {
    case (Action::Kind::Sleep):
    {
      response.result.sleep.started = TClock::now();
      std::this_thread::sleep_for(action.args.sleep.duration);
      response.result.sleep.ended = TClock::now();
      handle_response(std::move(response));
      break;
    }

    case (Action::Kind::Echo):
    {
      std::memcpy(
        response.result.echo.value,
        action.args.echo.original,
        sizeof(action.args.echo.original));
      if (action.args.echo.reverse)
      {
        std::reverse(
          std::begin(response.result.echo.value),
          std::end(response.result.echo.value));
      }
      handle_response(std::move(response));
      break;
    }

    default:
    {
      throw std::logic_error("Unhandled action kind in enact()");
    }
  }
}

void client_verify(const Action& action, const Response& response)
{
  REQUIRE_EQ(action.id, response.id);
  REQUIRE_EQ(action.kind, response.kind);

  switch (action.kind)
  {
    case (Action::Kind::Sleep):
    {
      const auto slept_time =
        response.result.sleep.ended - response.result.sleep.started;
      REQUIRE(slept_time >= action.args.sleep.duration);
      break;
    }

    case (Action::Kind::Echo):
    {
      TData expected;
      std::memcpy(expected, action.args.echo.original, sizeof(expected));
      if (action.args.echo.reverse)
      {
        std::reverse(std::begin(expected), std::end(expected));
      }
      REQUIRE(
        std::memcmp(response.result.echo.value, expected, sizeof(expected)) ==
        0);
      break;
    }

    default:
    {
      throw std::logic_error("Unhandled action kind in verify()");
    }
  }
}

struct ClientParams
{
  std::chrono::milliseconds submission_duration =
    std::chrono::milliseconds(100);

  std::function<void()> submission_delay = []() { std::this_thread::yield(); };

  std::function<Action()> generate_next_action = []() {
    if (rand() % 4 == 0)
    {
      return make_sleep_action(std::chrono::milliseconds(rand() % 5));
    }
    else
    {
      TData d;
      for (auto& b : d)
      {
        b = rand();
      }
      return make_echo_action(
        d,
        rand() % 2 == 0 // half of actions are reverse
      );
    }
  };

  ccf::tasks::LockingConcurrentQueue<Action> outgoing;
  ccf::tasks::LockingConcurrentQueue<Response> incoming;
};

using AllClientParams = std::array<ClientParams, NUM_CLIENTS>;

void client_thread(ClientParams& params)
{
  const auto start = TClock::now();
  const auto submission_end = start + params.submission_duration;

  std::queue<Action> pending_actions;

  while (true)
  {
    // For some period of time
    const bool still_submitting = TClock::now() < submission_end;
    if (still_submitting)
    {
      // Generate and submit new work
      Action a = params.generate_next_action();
      std::cout << "Generated action " << a.id << std::endl;
      pending_actions.push(a);
      params.outgoing.push_back(a);
    }

    // If we have any responses
    std::optional<Response> response = params.incoming.try_pop();
    while (response.has_value())
    {
      // Verify them (check that the first response matches the first pending
      // action)
      REQUIRE(!pending_actions.empty());
      client_verify(pending_actions.front(), response.value());
      pending_actions.pop();
      // ...and check for further responses
      response = params.incoming.try_pop();
    }

    // If we're finished submitting and have processed all responses
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
}

using ClientRequest = std::pair<size_t, Action>;
using ClientRequests = ccf::tasks::LockingConcurrentQueue<ClientRequest>;

struct DispatcherParams
{
  std::atomic<bool> stop_signal = false;

  AllClientParams& client_params;
  ClientRequests client_requests;
};

void dispatcher_thread(DispatcherParams& params)
{
  // Until told to stop
  while (!params.stop_signal)
  {
    // Read from each of the clients
    for (size_t i = 0; i < params.client_params.size(); ++i)
    {
      auto& client_params = params.client_params[i];
      auto action = client_params.outgoing.try_pop();
      while (action.has_value())
      {
        // Take any work they give us, and push it onto the task system's queue
        // TODO: Doing this naively like this leads to out-of-order execution,
        // and the test fails!
        params.client_requests.push_back(std::make_pair(i, action.value()));
        // ...and check for further work
        action = client_params.outgoing.try_pop();
      }
    }

    // Pause and repeat
    std::this_thread::yield();
  }
}

struct WorkerParams
{
  std::atomic<bool>& stop_signal;

  DispatcherParams& dispatcher;

  // Write direct responses?
  AllClientParams& clients;
};

void worker_thread(WorkerParams& params)
{
  // Until told to stop
  while (!params.stop_signal)
  {
    // Get a task
    auto client_request = params.dispatcher.client_requests.try_pop();
    while (client_request.has_value())
    {
      auto [client_id, action] = client_request.value();

      // Do the task
      // TODO: Some fraction of jobs should fail, some via timeout
      server_enact(action, [&params, client_id](Response&& response) {
        // Write response
        params.clients[client_id].incoming.push_back(response);
      });

      // ...and check for next task
      client_request = params.dispatcher.client_requests.try_pop();
    }

    // Pause and repeat
    std::this_thread::yield();
  }
}

TEST_CASE("Demo")
{
  AllClientParams client_params;

  std::vector<std::thread> clients;
  for (size_t i = 0; i < NUM_CLIENTS; ++i)
  {
    clients.emplace_back(client_thread, std::ref(client_params[i]));
  }

  DispatcherParams dispatcher_params{.client_params = client_params};
  std::thread dispatcher(dispatcher_thread, std::ref(dispatcher_params));

  std::atomic<bool> worker_stop_signal;

  std::vector<WorkerParams> worker_params;
  for (size_t i = 0; i < NUM_WORKERS; ++i)
  {
    worker_params.push_back(WorkerParams{
      .stop_signal = worker_stop_signal,
      .dispatcher = dispatcher_params,
      .clients = client_params});
  }

  std::vector<std::thread> workers;
  for (size_t i = 0; i < NUM_WORKERS; ++i)
  {
    workers.emplace_back(worker_thread, std::ref(worker_params[i]));
  }

  for (auto& client : clients)
  {
    client.join();
  }

  worker_stop_signal = true;

  for (auto& worker : workers)
  {
    worker.join();
  }

  dispatcher_params.stop_signal = true;

  dispatcher.join();
}