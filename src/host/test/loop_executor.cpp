// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "host/loop_executor.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <atomic>
#include <doctest/doctest.h>
#include <thread>
#include <vector>

using namespace asynchost;

TEST_CASE("LoopExecutor runs queued work on flush")
{
  LoopExecutorImpl executor;

  int counter = 0;
  executor.enqueue([&]() { counter += 1; });
  executor.enqueue([&]() { counter += 10; });

  // Nothing runs until flush()
  REQUIRE(counter == 0);

  executor.flush();
  REQUIRE(counter == 11);

  // A second flush with no pending work is a no-op
  executor.flush();
  REQUIRE(counter == 11);
}

TEST_CASE("LoopExecutor preserves enqueue order")
{
  LoopExecutorImpl executor;

  std::vector<int> order;
  constexpr int n = 100;
  for (int i = 0; i < n; ++i)
  {
    executor.enqueue([&order, i]() { order.push_back(i); });
  }

  executor.flush();

  REQUIRE(order.size() == n);
  for (int i = 0; i < n; ++i)
  {
    REQUIRE(order[i] == i);
  }
}

TEST_CASE("LoopExecutor defers work enqueued during flush")
{
  LoopExecutorImpl executor;

  int outer = 0;
  int inner = 0;
  executor.enqueue([&]() {
    outer += 1;
    // Work enqueued while flushing must not run during this same flush.
    executor.enqueue([&]() { inner += 1; });
  });

  executor.flush();
  REQUIRE(outer == 1);
  REQUIRE(inner == 0);

  // The re-entrantly enqueued work runs on the next flush.
  executor.flush();
  REQUIRE(outer == 1);
  REQUIRE(inner == 1);
}

TEST_CASE("LoopExecutor is safe under concurrent producers")
{
  LoopExecutorImpl executor;

  std::atomic<int> executed{0};
  std::atomic<bool> draining{true};

  constexpr int num_producers = 8;
  constexpr int per_producer = 10000;

  // A single "loop thread" continuously draining the executor.
  std::thread loop_thread([&]() {
    while (draining.load())
    {
      executor.flush();
    }
    // Final drain to catch anything enqueued just before we stopped.
    executor.flush();
  });

  std::vector<std::thread> producers;
  producers.reserve(num_producers);
  for (int p = 0; p < num_producers; ++p)
  {
    producers.emplace_back([&]() {
      for (int i = 0; i < per_producer; ++i)
      {
        executor.enqueue([&executed]() { executed.fetch_add(1); });
      }
    });
  }

  for (auto& t : producers)
  {
    t.join();
  }

  // Stop draining once all work has been enqueued; the loop thread will do a
  // final flush before exiting.
  draining.store(false);
  loop_thread.join();

  REQUIRE(executed.load() == num_producers * per_producer);
}
