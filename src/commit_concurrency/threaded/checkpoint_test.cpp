// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/crypto/sha256_hash.h"
#include "commit_concurrency/threaded/checkpoint.h"

#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
#include <atomic>
#include <doctest/doctest.h>
#include <thread>

// These tests exercise the Checkpoint/random_delay primitives entirely in
// isolation, with no Store/Raft/History involved, to validate the mechanism
// itself before it is relied upon elsewhere.

DOCTEST_TEST_CASE(
  "Checkpoint pauses a worker until explicitly released" *
  doctest::test_suite("checkpoint"))
{
  ccf::kv::test::Checkpoint checkpoint("test");
  std::atomic<bool> worker_progressed{false};

  std::thread worker([&]() {
    checkpoint.pause();
    worker_progressed = true;
  });

  checkpoint.wait_until_paused();
  // The worker must still be blocked in pause() at this point - there is no
  // way to observe this with perfect certainty without a race, but a short
  // delay makes a bug here overwhelmingly likely to be caught.
  std::this_thread::sleep_for(std::chrono::milliseconds(5));
  DOCTEST_CHECK_FALSE(worker_progressed.load());

  checkpoint.release();
  worker.join();
  DOCTEST_CHECK(worker_progressed.load());
}

DOCTEST_TEST_CASE(
  "Checkpoint can be reused for multiple sequential pause/release cycles" *
  doctest::test_suite("checkpoint"))
{
  ccf::kv::test::Checkpoint checkpoint;
  constexpr size_t cycles = 20;

  for (size_t i = 0; i < cycles; ++i)
  {
    std::atomic<size_t> progressed{0};
    std::thread worker([&]() {
      checkpoint.pause();
      progressed = i + 1;
    });

    checkpoint.wait_until_paused();
    checkpoint.release();
    worker.join();
    DOCTEST_REQUIRE(progressed.load() == i + 1);
  }
}

DOCTEST_TEST_CASE(
  "wait_until_paused_and_release is a one-shot happens-before edge" *
  doctest::test_suite("checkpoint"))
{
  ccf::kv::test::Checkpoint checkpoint;
  std::atomic<bool> worker_progressed{false};

  std::thread worker([&]() {
    checkpoint.pause();
    worker_progressed = true;
  });

  checkpoint.wait_until_paused_and_release();
  worker.join();
  DOCTEST_CHECK(worker_progressed.load());
}

DOCTEST_TEST_CASE(
  "checkpoint_write_set_observer pauses when invoked" *
  doctest::test_suite("checkpoint"))
{
  ccf::kv::test::Checkpoint checkpoint;
  auto observer = ccf::kv::test::checkpoint_write_set_observer(checkpoint);

  std::atomic<bool> worker_progressed{false};
  std::thread worker([&]() {
    observer(ccf::crypto::Sha256Hash(), std::string("evidence"));
    worker_progressed = true;
  });

  checkpoint.wait_until_paused();
  DOCTEST_CHECK_FALSE(worker_progressed.load());
  checkpoint.release();
  worker.join();
  DOCTEST_CHECK(worker_progressed.load());
}

DOCTEST_TEST_CASE(
  "random_delay respects its upper bound and can be zero" *
  doctest::test_suite("checkpoint"))
{
  std::mt19937 rng(1234);

  DOCTEST_INFO("A zero bound returns immediately");
  const auto before = std::chrono::steady_clock::now();
  ccf::kv::test::random_delay(rng, std::chrono::microseconds(0));
  const auto after = std::chrono::steady_clock::now();
  DOCTEST_CHECK(after - before < std::chrono::milliseconds(50));

  DOCTEST_INFO("A non-zero bound is respected, across many draws");
  constexpr auto bound = std::chrono::microseconds(2000);
  for (size_t i = 0; i < 100; ++i)
  {
    const auto start = std::chrono::steady_clock::now();
    ccf::kv::test::random_delay(rng, bound);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    // Generous upper margin for scheduling jitter - this is checking that
    // random_delay is bounded, not that it is precise.
    DOCTEST_CHECK(elapsed < bound + std::chrono::milliseconds(50));
  }
}
