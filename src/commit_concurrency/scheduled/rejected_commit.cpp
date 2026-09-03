// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "commit_concurrency/scheduled/deterministic_scheduler.h"
#include "commit_concurrency/threaded/fixture.h"

#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
#include <algorithm>
#include <doctest/doctest.h>
#include <fmt/format.h>

using namespace ccf::kv::test;

namespace
{
  // Actor 0 (or any writer actor): reads (fixing this transaction's
  // commit view), then attempts to commit an ordinary write.
  // yield_point() is an explicit point for the scheduler to consider
  // interleaving an election here, mirroring how a real thread could be
  // preempted at that instant even though nothing here takes a lock.
  void run_writer(CommitConcurrencyFixture& fixture, size_t key)
  {
    auto tx = fixture.store->create_tx();
    tx.rw(fixture.table)->put(key, key);
    yield_point(
      "read for a write to key " + std::to_string(key) + ", about to commit");
    tx.commit();
  }

  // Checks that replication has not permanently fallen behind the
  // Store's own version - if a write landed locally without reaching
  // consensus, a further ordinary commit must still let replication
  // catch up to it.
  bool replication_can_catch_up(CommitConcurrencyFixture& fixture)
  {
    auto later_tx = fixture.store->create_tx();
    later_tx.rw(fixture.table)->put(1000, 1000);
    later_tx.commit();
    return fixture.raft->get_last_idx() == fixture.store->current_txid().seqno;
  }
}

// Randomly samples interleavings of a transaction committing across a
// real election, rather than the one pinned interleaving in
// deterministic.cpp - see that file for the invariant being checked
// (also a regression test for #8242).
// estimate_schedule_count() below puts this scenario's interleaving space
// (every real lock acquisition is now a decision point, not just
// contended ones) far beyond what is practical to exhaust, so this
// samples a fixed, reproducible number of random schedules instead.
DOCTEST_TEST_CASE(
  "Randomly sampled: every sampled interleaving of a stale-view commit "
  "and a real election leaves replication able to catch up to the "
  "Store's own version" *
  doctest::test_suite("commit_concurrency_scheduled"))
{
  std::unique_ptr<CommitConcurrencyFixture> fixture;
  ccf::TxID baseline_txid;

  const auto make_run = [&]() -> std::vector<std::function<void()>> {
    fixture = std::make_unique<CommitConcurrencyFixture>();
    baseline_txid = fixture->commit_signature();
    return {[&]() { run_writer(*fixture, 0); }, [&]() { fixture->reelect(); }};
  };
  const auto on_schedule = [&](const DeterministicScheduler& scheduler) {
    if (fixture->store->current_txid().seqno != baseline_txid.seqno)
    {
      const auto description = "Schedule:\n" + scheduler.describe();
      DOCTEST_INFO(description);
      DOCTEST_CHECK(replication_can_catch_up(*fixture));
    }
  };

  const auto estimates = estimate_schedule_count(2, make_run);
  const double min_estimate =
    *std::min_element(estimates.begin(), estimates.end());
  const double max_estimate =
    *std::max_element(estimates.begin(), estimates.end());
  DOCTEST_MESSAGE(fmt::format(
    "Estimated schedule count for the single-writer scenario: {} to {}",
    min_estimate,
    max_estimate));

  constexpr size_t num_samples = 500;
  constexpr uint32_t seed = 42;
  DOCTEST_INFO(fmt::format(
    "Sampling {} of an estimated {}-{} schedules (seed {})",
    num_samples,
    min_estimate,
    max_estimate,
    seed));
  explore_random_interleavings(
    2, make_run, on_schedule, num_samples, seed, {"writer 0", "elector"});
}

// The same invariant as above, but with a second concurrent writer
// added. estimate_schedule_count() below puts this scenario's
// interleaving space even further beyond what is practical to exhaust
// (see the DOCTEST_MESSAGE this prints), so this samples a fixed,
// reproducible number of random schedules instead.
DOCTEST_TEST_CASE(
  "Randomly sampled: every sampled interleaving of two concurrent "
  "stale-view commits and a real election leaves replication able to "
  "catch up to the Store's own version" *
  doctest::test_suite("commit_concurrency_scheduled"))
{
  std::unique_ptr<CommitConcurrencyFixture> fixture;
  ccf::TxID baseline_txid;

  const auto make_run = [&]() -> std::vector<std::function<void()>> {
    fixture = std::make_unique<CommitConcurrencyFixture>();
    baseline_txid = fixture->commit_signature();
    return {
      [&]() { run_writer(*fixture, 0); },
      [&]() { run_writer(*fixture, 1); },
      [&]() { fixture->reelect(); }};
  };
  const auto on_schedule = [&](const DeterministicScheduler& scheduler) {
    if (fixture->store->current_txid().seqno != baseline_txid.seqno)
    {
      const auto description = "Schedule:\n" + scheduler.describe();
      DOCTEST_INFO(description);
      DOCTEST_CHECK(replication_can_catch_up(*fixture));
    }
  };

  const auto estimates = estimate_schedule_count(3, make_run);
  const double min_estimate =
    *std::min_element(estimates.begin(), estimates.end());
  const double max_estimate =
    *std::max_element(estimates.begin(), estimates.end());
  DOCTEST_MESSAGE(fmt::format(
    "Estimated schedule count for the two-writer scenario: {} to {} "
    "(compare with the single-writer scenario's estimate above)",
    min_estimate,
    max_estimate));

  constexpr size_t num_samples = 500;
  constexpr uint32_t seed = 42;
  DOCTEST_INFO(fmt::format(
    "Sampling {} of an estimated {}-{} schedules (seed {})",
    num_samples,
    min_estimate,
    max_estimate,
    seed));
  explore_random_interleavings(
    3,
    make_run,
    on_schedule,
    num_samples,
    seed,
    {"writer 0", "writer 1", "elector"});
}
