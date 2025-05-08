// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "./actions.h"
#include "./cancellable_task.h"
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
  auto set_2 = make_cancellable_task<BasicTask>([&x]() { x = 2; }, name_2);
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
  auto set_3 = make_cancellable_task<BasicTask>([&x]() { x = 3; }, name_3);
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

void describe_job_board(JobBoard& jb)
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
  describe_job_board((JobBoard&)d.state.job_board);

  fmt::print(
    "Dispatcher is tracking {} sessions\n",
    d.state.ordered_tasks_per_client.size());

  for (auto& [session, tasks] : d.state.ordered_tasks_per_client)
  {
    fmt::print(
      "  {}: {} (active: {}, queue.size: {})\n",
      session->name,
      tasks->get_name(),
      tasks->sub_tasks.active,
      tasks->sub_tasks.queue.size());
  }
}

TEST_CASE("Run")
{
  size_t total_requests_sent = 0;
  size_t total_responses_seen = 0;
  size_t total_tasks_processed = 0;

  {
    // Create a node
    JobBoard job_board;
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

    node.dispatcher.state.consider_ternination.store(true);
    node.dispatcher.shutdown();

    describe_dispatcher(node.dispatcher);

    for (auto& worker : node.workers)
    {
      worker->state.consider_termination.store(true);
      worker->shutdown();
      total_tasks_processed += worker->state.work_completed;
    }

    // Validate results?
    // Validate clean shutdown?
    // Print some metrics?
  }

  LOG_INFO_FMT(
    "{} vs {} vs {}",
    total_requests_sent,
    total_responses_seen,
    total_tasks_processed);
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