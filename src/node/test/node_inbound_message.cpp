// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../node_inbound_message.h"

#include "tasks/job_board.h"
#include "tasks/worker.h"

#include <atomic>
#include <doctest/doctest.h>
#include <optional>
#include <stdexcept>
#include <thread>
#include <vector>

namespace
{
  // Records the most recent message passed to it, so a test can assert whether
  // (and with what arguments) a particular handler was invoked.
  struct StubHandler
  {
    std::optional<ccf::NodeId> last_from;
    std::vector<uint8_t> last_payload;
    size_t call_count = 0;

    void recv_message(const ccf::NodeId& from, const uint8_t* data, size_t size)
    {
      last_from = from;
      last_payload.assign(data, data + size);
      ++call_count;
    }

    void recv_channel_message(
      const ccf::NodeId& from, const uint8_t* data, size_t size)
    {
      recv_message(from, data, size);
    }
  };

  void run_all(ccf::tasks::JobBoard& job_board)
  {
    while (auto task = job_board.get_task())
    {
      task->do_task();
    }
  }
}

TEST_CASE(
  "node inbound message gate and dispatch" *
  doctest::test_suite("node_inbound_message"))
{
  const ccf::NodeId from("0123456789abcdef");
  const std::vector<uint8_t> payload{1, 2, 3, 4, 5};

  const auto early_states = {
    ccf::NodeStartupState::uninitialized,
    ccf::NodeStartupState::initialized,
    ccf::NodeStartupState::pending,
    ccf::NodeStartupState::readingPublicLedger};

  const auto active_states = {
    ccf::NodeStartupState::partOfNetwork,
    ccf::NodeStartupState::partOfPublicNetwork,
    ccf::NodeStartupState::readingPrivateLedger};

  SUBCASE("Caller gate rejects early states")
  {
    for (const auto state : early_states)
    {
      INFO("Early state: ", state);
      ds::StateMachine<ccf::NodeStartupState> sm("test", state);
      REQUIRE(!ccf::can_process_node_inbound_message(sm));
    }
  }

  SUBCASE("Caller gate accepts active states")
  {
    for (const auto state : active_states)
    {
      INFO("Active state: ", state);
      ds::StateMachine<ccf::NodeStartupState> sm("test", state);
      REQUIRE(ccf::can_process_node_inbound_message(sm));
    }
  }

  SUBCASE("Forwarded commands dispatch to command forwarder")
  {
    StubHandler forwarder;
    StubHandler channels;
    StubHandler consensus;

    ccf::recv_node_inbound_message(
      ccf::forwarded_msg,
      from,
      payload.data(),
      payload.size(),
      &forwarder,
      &channels,
      &consensus);

    REQUIRE(forwarder.call_count == 1);
    REQUIRE(forwarder.last_from == from);
    REQUIRE(forwarder.last_payload == payload);
    REQUIRE(channels.call_count == 0);
    REQUIRE(consensus.call_count == 0);
  }

  SUBCASE("Channel messages dispatch to node-to-node channels")
  {
    StubHandler forwarder;
    StubHandler channels;
    StubHandler consensus;

    ccf::recv_node_inbound_message(
      ccf::channel_msg,
      from,
      payload.data(),
      payload.size(),
      &forwarder,
      &channels,
      &consensus);

    REQUIRE(channels.call_count == 1);
    REQUIRE(channels.last_from == from);
    REQUIRE(channels.last_payload == payload);
    REQUIRE(forwarder.call_count == 0);
    REQUIRE(consensus.call_count == 0);
  }

  SUBCASE("Consensus messages dispatch to consensus")
  {
    StubHandler forwarder;
    StubHandler channels;
    StubHandler consensus;

    ccf::recv_node_inbound_message(
      ccf::consensus_msg,
      from,
      payload.data(),
      payload.size(),
      &forwarder,
      &channels,
      &consensus);

    REQUIRE(consensus.call_count == 1);
    REQUIRE(consensus.last_from == from);
    REQUIRE(consensus.last_payload == payload);
    REQUIRE(forwarder.call_count == 0);
    REQUIRE(channels.call_count == 0);
  }

  SUBCASE("Unknown message types are rejected")
  {
    StubHandler forwarder;
    StubHandler channels;
    StubHandler consensus;

    REQUIRE_THROWS_AS(
      ccf::recv_node_inbound_message(
        static_cast<ccf::NodeMsgType>(42),
        from,
        payload.data(),
        payload.size(),
        &forwarder,
        &channels,
        &consensus),
      std::logic_error);
    REQUIRE(forwarder.call_count == 0);
    REQUIRE(channels.call_count == 0);
    REQUIRE(consensus.call_count == 0);
  }
}

TEST_CASE("Node ingress lane" * doctest::test_suite("node_inbound_message"))
{
  const ccf::NodeId peer("0123456789abcdef");

  SUBCASE("Inbound messages and node work run in submission order")
  {
    ccf::tasks::JobBoard job_board;
    std::vector<std::string> seen;
    ccf::NodeIngress ingress(
      job_board,
      [&](ccf::NodeMsgType, const ccf::NodeId&, const uint8_t* d, size_t n) {
        seen.emplace_back(d, d + n);
      });

    ingress.recv_node_inbound(
      ccf::consensus_msg, peer, std::vector<uint8_t>{'a'});
    ingress.submit("tick", [&]() { seen.emplace_back("tick"); });
    ingress.recv_node_inbound(
      ccf::channel_msg, peer, std::vector<uint8_t>{'b'});

    REQUIRE(seen.empty());
    run_all(job_board);
    REQUIRE(seen == std::vector<std::string>{"a", "tick", "b"});
  }

  SUBCASE("The lane is a critical task")
  {
    ccf::tasks::JobBoard job_board;
    size_t received = 0;
    ccf::NodeIngress ingress(
      job_board,
      [&](ccf::NodeMsgType, const ccf::NodeId&, const uint8_t*, size_t) {
        ++received;
      });

    ingress.recv_node_inbound(ccf::consensus_msg, peer, {});
    auto task = job_board.get_critical_task();
    REQUIRE(task != nullptr);
    REQUIRE(task->get_task_class() == ccf::tasks::TaskClass::Critical);
    task->do_task();
    REQUIRE(received == 1);
  }

  SUBCASE("Queued payloads are owned by the lane")
  {
    ccf::tasks::JobBoard job_board;
    std::vector<uint8_t> received;
    ccf::NodeIngress ingress(
      job_board,
      [&](ccf::NodeMsgType, const ccf::NodeId&, const uint8_t* d, size_t n) {
        received.assign(d, d + n);
      });

    {
      // Stands in for the transport's read buffer, reused after delivery
      std::vector<uint8_t> read_buffer{1, 2, 3, 4};
      ingress.recv_node_inbound(
        ccf::consensus_msg,
        peer,
        std::vector<uint8_t>(read_buffer.begin(), read_buffer.end()));
      std::fill(read_buffer.begin(), read_buffer.end(), 0xff);
    }

    run_all(job_board);
    REQUIRE(received == std::vector<uint8_t>{1, 2, 3, 4});
  }

  SUBCASE("A malformed message is dropped without affecting later ones")
  {
    ccf::tasks::JobBoard job_board;
    size_t processed = 0;
    ccf::NodeIngress ingress(
      job_board,
      [&](ccf::NodeMsgType, const ccf::NodeId&, const uint8_t* d, size_t n) {
        if (n == 0)
        {
          throw std::logic_error("Malformed");
        }
        ++processed;
      });

    ingress.recv_node_inbound(ccf::consensus_msg, peer, {});
    ingress.recv_node_inbound(
      ccf::consensus_msg, peer, std::vector<uint8_t>{1});

    // A task exception would abort here, as production workers do
    while (auto task = job_board.get_task())
    {
      ccf::tasks::try_do_task(*task);
    }
    REQUIRE(processed == 1);
  }

  SUBCASE("Work is rejected after stop and discarded at board shutdown")
  {
    ccf::tasks::JobBoard job_board;
    size_t received = 0;
    ccf::NodeIngress ingress(
      job_board,
      [&](ccf::NodeMsgType, const ccf::NodeId&, const uint8_t*, size_t) {
        ++received;
      });

    ingress.recv_node_inbound(ccf::consensus_msg, peer, {});
    ingress.stop();
    ingress.recv_node_inbound(ccf::consensus_msg, peer, {});
    bool submitted_ran = false;
    ingress.submit("tick", [&]() { submitted_ran = true; });

    job_board.shutdown();
    run_all(job_board);
    REQUIRE(received == 0);
    REQUIRE_FALSE(submitted_ran);
  }

  SUBCASE("Inbound messages and node work never run concurrently")
  {
    ccf::tasks::JobBoard job_board;
    std::atomic<size_t> active = 0;
    std::atomic<bool> overlapped = false;
    std::atomic<size_t> done = 0;
    const auto body = [&]() {
      if (active.fetch_add(1) != 0)
      {
        overlapped = true;
      }
      std::this_thread::yield();
      active.fetch_sub(1);
      done.fetch_add(1);
    };

    ccf::NodeIngress ingress(
      job_board,
      [&](ccf::NodeMsgType, const ccf::NodeId&, const uint8_t*, size_t) {
        body();
      });

    std::atomic<bool> stop = false;
    std::vector<std::thread> workers;
    for (size_t i = 0; i < 4; ++i)
    {
      workers.emplace_back(
        [&]() { ccf::tasks::task_worker_loop(job_board, stop); });
    }

    constexpr size_t each = 500;
    std::thread producer([&]() {
      for (size_t i = 0; i < each; ++i)
      {
        ingress.recv_node_inbound(ccf::consensus_msg, peer, {});
      }
    });
    for (size_t i = 0; i < each; ++i)
    {
      ingress.submit("tick", body);
    }
    producer.join();

    while (done.load() < 2 * each)
    {
      std::this_thread::yield();
    }
    stop = true;
    job_board.stop_waiters();
    for (auto& worker : workers)
    {
      worker.join();
    }

    REQUIRE_FALSE(overlapped.load());
  }
}
