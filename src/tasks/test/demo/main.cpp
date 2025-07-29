// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "./actions.h"
#include "./clients.h"
#include "./node.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

// Writing a bunch of code here, so run a few simple sanity checks that the
// basic operations do what we expect
TEST_CASE("SignAction")
{
  for (size_t i = 0; i < 100; ++i)
  {
    auto orig = std::make_unique<SignAction>();
    auto ser = orig->serialise();

    auto received = deserialise_action(ser);
    auto result = received->do_action();

    orig->verify_serialised_response(result);
  }
}

TEST_CASE("Tasks")
{
  size_t x = 0;

  // Basic tasks
  const std::string name_1 = "Set x to 1";
  auto set_1 = make_basic_task([&x]() { x = 1; }, name_1);
  REQUIRE(set_1->get_name() == name_1);
  REQUIRE(x == 0);
  set_1->do_task();
  REQUIRE(x == 1);

  // Cancelling pre-execution
  const std::string name_2 = "Set x to 2";
  auto set_2 = make_basic_task([&x]() { x = 2; }, name_2);
  REQUIRE(set_2->get_name() == name_2);
  REQUIRE(x == 1);
  REQUIRE_FALSE(set_2->is_cancelled());
  set_2->cancel_task();
  REQUIRE(set_2->is_cancelled());
  set_2->do_task();
  REQUIRE(set_2->is_cancelled());
  REQUIRE(x == 1);

  // Cancelling post-execution
  const std::string name_3 = "Set x to 3";
  auto set_3 = make_basic_task([&x]() { x = 3; }, name_3);
  REQUIRE(set_3->get_name() == name_3);
  REQUIRE(x == 1);
  REQUIRE_FALSE(set_3->is_cancelled());
  set_3->do_task();
  REQUIRE(x == 3);
  REQUIRE_FALSE(set_3->is_cancelled());
  set_3->cancel_task();
  REQUIRE(set_3->is_cancelled());
  REQUIRE(x == 3);
}

TEST_CASE("OrderedTasks")
{
  // With more sessions than workers, and tasks concurrently added to these
  // sessions, each task is still executed in-order for that session
  static constexpr auto num_sessions = 5;
  static constexpr auto num_workers = 2;

  // Record last x seen for each session
  using Result = std::atomic<size_t>;
  std::vector<Result> results(num_sessions);

  ccf::tasks::JobBoard job_board;
  {
    // Record next x to send for each session
    std::vector<std::pair<std::shared_ptr<ccf::tasks::OrderedTasks>, size_t>> all_tasks;
    for (auto i = 0; i < num_sessions; ++i)
    {
      all_tasks.emplace_back(
        std::make_shared<ccf::tasks::OrderedTasks>(job_board, std::to_string(i)), 0);
    }

    auto add_action = [&](size_t idx, size_t sleep_time_ms) {
      auto& [tasks, n] = all_tasks[idx];
      tasks->add_action(ccf::tasks::make_basic_action([=, &n, &results]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_time_ms));
        const auto x = ++n;
        LOG_TRACE_FMT("{} {}", tasks->get_name(), x);
        REQUIRE(++results[idx] == x);
      }));
    };

    // Add some initial tasks on each session
    const auto spacing = 3;
    const auto period = spacing * num_sessions + 1;
    for (auto i = 0; i < num_sessions; ++i)
    {
      add_action(i, spacing * i);
      add_action(i, period);
      add_action(i, period);
    }

    {
      std::vector<std::unique_ptr<Worker>> workers;
      for (auto i = 0; i < num_workers; ++i)
      {
        workers.emplace_back(std::make_unique<Worker>(job_board, i));
      }

      // Start processing those tasks on worker threads
      for (auto& worker : workers)
      {
        worker->start();
      }

      // Continually add tasks, while the workers are running
      for (auto i = 0; i < num_workers * num_sessions * 10; ++i)
      {
        add_action(i % all_tasks.size(), period);
        // Try to produce an interesting interleaving of tasks across sessions
        if (i % ((num_workers * num_sessions) - 1) == 0)
        {
          std::this_thread::sleep_for(std::chrono::milliseconds(period / 2));
        }
      }

      while (!job_board.empty())
      {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
    }
  }
}

TEST_CASE("PauseAndResume")
{
  ccf::tasks::JobBoard job_board;
  {
    size_t x = 0;
    size_t y = 0;

    auto increment = [](size_t& n) {
      return ccf::tasks::make_basic_action([&n]() { ++n; });
    };

    std::shared_ptr<ccf::tasks::OrderedTasks> x_tasks =
      std::make_shared<ccf::tasks::OrderedTasks>(job_board, "x");
    std::shared_ptr<ccf::tasks::OrderedTasks> y_tasks =
      std::make_shared<ccf::tasks::OrderedTasks>(job_board, "y");

    x_tasks->add_action(increment(x));
    y_tasks->add_action(increment(y));
    y_tasks->add_action(increment(y));

    {
      Worker worker(job_board, 0);

      // Worker exists but hasn't started yet - no increments have occurred
      REQUIRE(x == 0);
      REQUIRE(y == 0);

      // Even if we wait
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      REQUIRE(x == 0);
      REQUIRE(y == 0);

      // If we start the worker (and wait), it will execute the pending tasks
      worker.start();
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      REQUIRE(x == 1);
      REQUIRE(y == 2);

      // We can concurrently queue many more tasks, which will be executed
      // immediately
      for (auto i = 0; i < 100; ++i)
      {
        x_tasks->add_action(increment(x));
        y_tasks->add_action(increment(y));
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      REQUIRE(x == 101);
      REQUIRE(y == 102);
    }

    {
      // Terminating previous worker, creating a new one (not yet running)
      Worker worker(job_board, 1);

      // If we need to block, we can ask for a task to be paused. Note that the
      // current action will still complete
      bool happened = false;
      ccf::tasks::Resumable resumable;

      x_tasks->add_action(increment(x));
      x_tasks->add_action(ccf::tasks::make_basic_action([&]() {
        // NB: This doesn't need to _know_ the current task, just that it is
        // executed _as part of a task_. This means it could occur deep within a
        // call-stack.
        resumable = ccf::tasks::pause_current_task();
        // NB: The current _action_ will still complete execution!
        happened = true;
      }));
      x_tasks->add_action(increment(x));

      worker.start();
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      REQUIRE(x == 102); // One increment action happened
      REQUIRE(happened == true); // Then the pause action ran to completion
      REQUIRE(
        resumable != nullptr); // We got a handle to later resume this task

      // Other actions can be scheduled, including on the paused task.
      // Unpaused tasks will complete as normal.
      for (auto i = 0; i < 100; ++i)
      {
        x_tasks->add_action(increment(x));
        y_tasks->add_action(increment(y));
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      REQUIRE(x == 102);
      REQUIRE(y == 202);

      // After resume, all queued actions will (be able to) execute, in-order
      ccf::tasks::resume_task(std::move(resumable));

      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      REQUIRE(x == 203);
      REQUIRE(y == 202);

      // A task might be paused multiple times during its life
      resumable = nullptr;
      x_tasks->add_action(increment(x));
      x_tasks->add_action(ccf::tasks::make_basic_action(
        [&]() { resumable = ccf::tasks::pause_current_task(); }));
      x_tasks->add_action(increment(x));

      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      REQUIRE(x == 204);
      REQUIRE(resumable != nullptr);

      // A paused task can be cancelled
      x_tasks->cancel_task();

      // Cancellation supercedes resumption - nothing more happens on this task
      ccf::tasks::resume_task(std::move(resumable));

      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      REQUIRE(x == 204);
    }
  }

  // Trying to pause outside of a task will throw an error
  REQUIRE_THROWS(ccf::tasks::pause_current_task());
}

void describe_session_manager(SessionManager& sm)
{
  std::lock_guard<std::mutex> lock(sm.sessions_mutex);
  fmt::print("SessionManager contains {} sessions\n", sm.all_sessions.size());
  for (auto& session : sm.all_sessions)
  {
    fmt::print(
      "  {}: {} to_node, {} from_node\n",
      session->name,
      session->to_node.size(),
      session->from_node.size());
  }
}

void describe_job_board(ccf::tasks::JobBoard& jb)
{
  std::lock_guard<std::mutex> lock(jb.mutex);
  fmt::print("JobBoard contains {} tasks\n", jb.queue.size());
  // for (auto& task : jb.queue)
  // {
  //   fmt::print("  {}\n", task->get_name());
  // }
}

void describe_dispatcher(Dispatcher& d)
{
  describe_session_manager(d.state.session_manager);
  describe_job_board((ccf::tasks::JobBoard&)d.state.job_board);

  fmt::print(
    "Dispatcher is tracking {} sessions\n",
    d.state.ordered_tasks_per_client.size());

  for (auto& [session, tasks] : d.state.ordered_tasks_per_client)
  {
    fmt::print(
      "  {}: {} (active: {}, queue.size: {})\n",
      session->name,
      tasks->get_name(),
      tasks->actions.active,
      tasks->actions.pending.size());
  }
}

TEST_CASE("Run")
{
  size_t total_requests_sent = 0;
  size_t total_responses_seen = 0;
  size_t total_tasks_processed = 0;

  {
    // Create a node
    ccf::tasks::JobBoard job_board;
    Node node(4, job_board);
    node.start();

    {
      // Create some clients
      ClientParams client_params;
      std::vector<std::unique_ptr<Client>> clients;
      for (auto i = 0u; i < 12; ++i)
      {
        clients.push_back(std::make_unique<Client>(
          node.new_session(std::to_string(i)), client_params, i));
        clients.back()->start();
      }

      LOG_INFO_FMT("Leaving to run");

      // Run everything, checking if all clients are done
      const auto n_clients = clients.size();
      while (true)
      {
        size_t running = 0;
        size_t shutting_down = 0;
        for (auto& client : clients)
        {
          const auto stage = client->lifetime_stage.load();
          if (stage <= Stage::Running)
          {
            ++running;
          }
          else if (stage == Stage::ShuttingDown)
          {
            ++shutting_down;
          }
        }
        LOG_INFO_FMT(
          "{} clients running (submitting), {} shutting down (checking "
          "responses), ({} total) ...",
          running,
          shutting_down,
          n_clients);
        if (running + shutting_down == 0)
        {
          break;
        }
        else
        {
          std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
      }

      for (auto& client : clients)
      {
        total_requests_sent += client->state.requests_sent;
        total_responses_seen += client->state.responses_seen;
      }

      LOG_INFO_FMT(
        "Shutting down clients, total sent: {}, total seen: {}",
        total_requests_sent,
        total_responses_seen);
    }

    node.dispatcher.state.consider_termination.store(true);
    node.dispatcher.shutdown();

    describe_dispatcher(node.dispatcher);

    for (auto& worker : node.workers)
    {
      worker->state.consider_termination.store(true);
      worker->shutdown();
      total_tasks_processed += worker->state.work_completed;
    }

    // TODO
    // Validate results?
    // Validate clean shutdown?
    // Print some metrics?
  }

  LOG_INFO_FMT(
    "{} vs {} vs {}",
    total_requests_sent,
    total_tasks_processed,
    total_responses_seen);

  REQUIRE(total_requests_sent >= total_tasks_processed);
  REQUIRE(total_tasks_processed >= total_responses_seen);
}

int main(int argc, char** argv)
{
  // ccf::tasks::TaskSystem::init();
  ccf::logger::config::default_init();
  ccf::logger::config::level() = ccf::LoggerLevel::INFO;

  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}

// TODO: Cancellation, deferment, error responses