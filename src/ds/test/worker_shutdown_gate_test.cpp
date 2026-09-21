// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/worker_shutdown_gate.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <atomic>
#include <chrono>
#include <doctest/doctest.h>
#include <future>
#include <thread>
#include <vector>

using namespace ccf::ds;

TEST_CASE("WorkerShutdownGate: basic registration and unregistration")
{
  WorkerShutdownGate gate;

  REQUIRE(gate.try_register());
  REQUIRE_FALSE(gate.is_shutting_down());
  gate.unregister();

  // Multiple registrations
  REQUIRE(gate.try_register());
  REQUIRE(gate.try_register());
  gate.unregister();
  gate.unregister();
}

TEST_CASE("WorkerShutdownGate: shutdown with no workers completes immediately")
{
  WorkerShutdownGate gate;
  gate.shutdown_and_wait();
  REQUIRE(gate.is_shutting_down());
}

TEST_CASE("WorkerShutdownGate: registration rejected after shutdown")
{
  WorkerShutdownGate gate;
  gate.shutdown_and_wait();
  REQUIRE_FALSE(gate.try_register());
}

TEST_CASE("WorkerShutdownGate: shutdown blocks until worker finishes")
{
  WorkerShutdownGate gate;
  REQUIRE(gate.try_register());

  std::promise<void> shutdown_started;
  std::promise<void> shutdown_done;

  std::thread shutdown_thread([&]() {
    shutdown_started.set_value();
    gate.shutdown_and_wait();
    shutdown_done.set_value();
  });

  // Wait for shutdown to begin
  shutdown_started.get_future().wait();

  // Shutdown should be blocked
  auto done_future = shutdown_done.get_future();
  REQUIRE(
    done_future.wait_for(std::chrono::milliseconds(200)) ==
    std::future_status::timeout);

  // Worker finishes - shutdown should complete
  gate.unregister();
  REQUIRE(
    done_future.wait_for(std::chrono::seconds(5)) == std::future_status::ready);

  shutdown_thread.join();
}

TEST_CASE("WorkerShutdownGate: shutdown blocks until all workers finish")
{
  WorkerShutdownGate gate;
  constexpr size_t num_workers = 5;

  for (size_t i = 0; i < num_workers; ++i)
  {
    REQUIRE(gate.try_register());
  }

  std::promise<void> shutdown_done;
  std::thread shutdown_thread([&]() {
    gate.shutdown_and_wait();
    shutdown_done.set_value();
  });

  auto done_future = shutdown_done.get_future();

  // Unregister all but one - should still be blocked
  for (size_t i = 0; i < num_workers - 1; ++i)
  {
    gate.unregister();
    REQUIRE(
      done_future.wait_for(std::chrono::milliseconds(50)) ==
      std::future_status::timeout);
  }

  // Last worker finishes
  gate.unregister();
  REQUIRE(
    done_future.wait_for(std::chrono::seconds(5)) == std::future_status::ready);

  shutdown_thread.join();
}

TEST_CASE(
  "WorkerShutdownGate: concurrent registration attempts during shutdown")
{
  WorkerShutdownGate gate;
  REQUIRE(gate.try_register());

  std::atomic<size_t> rejected_count{0};
  std::atomic<bool> go{false};

  // Launch threads that will try to register concurrently
  constexpr size_t num_threads = 10;
  std::vector<std::thread> threads;
  threads.reserve(num_threads);

  for (size_t i = 0; i < num_threads; ++i)
  {
    threads.emplace_back([&]() {
      while (!go.load())
      {
        std::this_thread::yield();
      }
      if (!gate.try_register())
      {
        ++rejected_count;
      }
      else
      {
        gate.unregister();
      }
    });
  }

  // Start shutdown (blocks because one worker is registered)
  std::thread shutdown_thread([&]() {
    // Give racers a moment to spin up
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    go.store(true);
    // Small delay so some racers hit try_register before/after shutdown
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    gate.unregister();
    gate.shutdown_and_wait();
  });

  shutdown_thread.join();
  for (auto& t : threads)
  {
    t.join();
  }

  // After shutdown, all subsequent registrations must be rejected
  REQUIRE_FALSE(gate.try_register());
}
