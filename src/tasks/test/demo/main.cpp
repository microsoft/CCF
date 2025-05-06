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
  for (size_t i = 0; i < 10; ++i)
  {
    auto orig = std::make_unique<SignAction>();
    auto ser = orig->serialise();

    auto received = deserialise_action(ser);
    auto result = received->do_action();

    orig->verify_serialised_response(result);
  }
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

      LOG_INFO_FMT("Shutting down clients");
    }

    describe_dispatcher(node.dispatcher);

    // Validate results?
    // Validate clean shutdown?
    // Print some metrics?
  }
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