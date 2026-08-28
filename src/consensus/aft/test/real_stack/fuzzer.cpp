// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "consensus/aft/test/real_stack/fixture.h"

#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
#include <atomic>
#include <charconv>
#include <cstdlib>
#include <doctest/doctest.h>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <vector>

// The randomised, multi-actor complement to deterministic.cpp's pinned
// scenarios. Drives a real Store + real Aft + real MerkleTxHistory
// (RealStackFixture) with:
//  - N writer threads, each committing ordinary transactions in a loop.
//  - One election-churn actor, repeatedly winning a fresh real election via
//    RealStackFixture::reelect().
//  - One reader thread, continuously polling
//    TxHistory::get_replicated_state_txid_and_root() and
//    Store::current_txid() concurrently, checking this suite's core
//    invariants on every poll.
//
// All randomness is drawn from a single seed (overridable via the RNG_SEED
// environment variable), logged unconditionally so any CI failure is
// re-runnable with the same seed. A real-OS-thread fuzzer is not
// byte-for-byte replayable purely from a seed - actual thread scheduling
// still varies run to run - so "reproducible" here means the same seed
// reliably exercises the same kind of interleaving, not an identical trace.
//
// The invariant checks below read two pieces of state that are each
// updated independently, with no shared synchronisation between the two
// reads that make up each check. Each check therefore reads its
// "reference" value both before and after the other read, with a short
// sleep in between, and only trusts the comparison if that reference value
// was unchanged across the whole window - this keeps the false-positive
// rate from this kind of read-only race negligible, without requiring any
// change to production code.

using namespace ccf::kv::test;

namespace
{
  uint32_t pick_seed()
  {
    if (const char* env = std::getenv("RNG_SEED"))
    {
      std::string rng_seed(env);
      uint32_t seed = 0;
      std::from_chars(rng_seed.data(), rng_seed.data() + rng_seed.size(), seed);
      if (seed != 0)
      {
        return seed;
      }
    }
    return std::random_device{}();
  }

  // Accumulates the first invariant violation found by the reader thread,
  // if any. Checked continuously (not just at the end) - see this file's
  // top comment.
  class InvariantViolations
  {
    std::mutex lock;
    std::optional<std::string> first;

  public:
    void record(const std::string& msg)
    {
      std::lock_guard<std::mutex> guard(lock);
      if (!first.has_value())
      {
        first = msg;
      }
    }

    std::optional<std::string> get()
    {
      std::lock_guard<std::mutex> guard(lock);
      return first;
    }
  };

  struct FuzzConfig
  {
    size_t num_writers = 4;
    size_t writer_iterations = 150;
    size_t reelection_iterations = 60;
    std::chrono::microseconds max_writer_delay{100};
    std::chrono::microseconds max_reelection_delay{500};
    bool use_real_crypto = false;
  };

  void run_fuzz(uint32_t seed, const FuzzConfig& cfg)
  {
    fmt::println(
      "real_stack fuzzer seed: {} (rerun with RNG_SEED={} to reproduce)",
      seed,
      seed);
    std::mt19937 seed_rng(seed);

    RealStackFixture fixture(cfg.use_real_crypto);
    const auto baseline_txid = fixture.commit_signature();

    InvariantViolations violations;
    std::atomic<bool> stop{false};

    // Reader actor: continuously polls TxHistory and the Store concurrently
    // and checks that they agree.
    std::thread reader([&]() {
      while (!stop.load())
      {
        // See this file's top comment for why each check below reads its
        // "reference" value both before and after the other side, with a
        // short sleep in between.
        const auto store_txid_before = fixture.store->current_txid();
        const auto history_txid = fixture.history_txid();
        std::this_thread::sleep_for(std::chrono::microseconds(20));
        const auto store_txid_after = fixture.store->current_txid();
        if (
          store_txid_before == store_txid_after &&
          history_txid.seqno > store_txid_after.seqno)
        {
          violations.record(fmt::format(
            "TxHistory reports seqno {} ahead of Store's own current_txid "
            "seqno {} (history TxID {}, store TxID {})",
            history_txid.seqno,
            store_txid_after.seqno,
            history_txid.to_str(),
            store_txid_after.to_str()));
        }

        // history_term_of_next_version() (unlike history_txid().view - see
        // the comment on RealStackFixture::history_txid()) is refreshed on
        // every rollback() to whatever term Aft passes at that moment, so
        // it must never be ahead of Aft's own current view. It can
        // legitimately lag transiently, since reelect() is two steps: a
        // message bumping Aft's view, then a separate call that performs
        // the rollback syncing history to it.
        const auto raft_view_before = fixture.raft->get_view();
        const auto history_current_view =
          fixture.history_term_of_next_version();
        std::this_thread::sleep_for(std::chrono::microseconds(20));
        const auto raft_view_after = fixture.raft->get_view();
        if (
          raft_view_before == raft_view_after &&
          history_current_view > raft_view_after)
        {
          violations.record(fmt::format(
            "TxHistory's own idea of the current term ({}) is ahead of "
            "Aft's own current view ({})",
            history_current_view,
            raft_view_after));
        }
      }
    });

    std::vector<std::thread> writers;
    writers.reserve(cfg.num_writers);
    for (size_t w = 0; w < cfg.num_writers; ++w)
    {
      const uint32_t writer_seed = seed_rng();
      writers.emplace_back([&fixture, &cfg, w, writer_seed]() {
        std::mt19937 rng(writer_seed);
        for (size_t i = 0; i < cfg.writer_iterations; ++i)
        {
          random_delay(rng, cfg.max_writer_delay);
          auto tx = fixture.store->create_tx();
          tx.rw(fixture.table)->put((w * 1'000'000) + i, i);
          // Any result is acceptable here - conflicts and rollback-induced
          // failures are expected and simply retried with a fresh
          // transaction on the next iteration.
          tx.commit();
        }
      });
    }

    const uint32_t churn_seed = seed_rng();
    std::thread election_churn([&fixture, &cfg, churn_seed]() {
      std::mt19937 rng(churn_seed);
      for (size_t i = 0; i < cfg.reelection_iterations; ++i)
      {
        random_delay(rng, cfg.max_reelection_delay);
        fixture.reelect();
      }
    });

    for (auto& w : writers)
    {
      w.join();
    }
    election_churn.join();

    // Stop the reader only once all mutating actors are done, then take one
    // final poll before it exits.
    stop = true;
    reader.join();

    const auto mid_run_violation = violations.get();
    DOCTEST_INFO(fmt::format("Seed was {}", seed));
    DOCTEST_REQUIRE_MESSAGE(
      !mid_run_violation.has_value(), mid_run_violation.value_or(""));

    DOCTEST_INFO(
      "After all actors quiesce, one final, fully deterministic election "
      "settles the Store at the permanently-safe baseline used throughout "
      "this fuzz run (no further signature was emitted during the fuzzing, "
      "so the one committed at the start remains the only globally "
      "committable index, and every election - including this final one - "
      "rolls back to it)");
    fixture.reelect();

    const auto final_txid = fixture.store->current_txid();
    DOCTEST_INFO(fmt::format("Seed was {}", seed));
    DOCTEST_CHECK(final_txid == baseline_txid);
    DOCTEST_CHECK(fixture.history_txid() == final_txid);
    DOCTEST_CHECK(fixture.raft->get_committed_seqno() == final_txid.seqno);
    DOCTEST_CHECK(fixture.raft->get_view(final_txid.seqno) == final_txid.view);
  }
}

DOCTEST_TEST_CASE(
  "Fuzz: concurrent writers, election churn, and a continuous reader keep "
  "TxHistory consistent with the Store (fast, NullTxEncryptor)" *
  doctest::test_suite("real_stack_fuzz"))
{
  // The writer threads and election_churn thread spawned by run_fuzz()
  // below run fully concurrently with no synchronisation between them, so
  // this currently exercises NOTE_IS_PRIMARY_RACE (see
  // RealStackFixture::reelect() in fixture.h). Expect this test to fail
  // occasionally, or to abort the whole process under ThreadSanitizer,
  // until that race is fixed.
  run_fuzz(pick_seed(), FuzzConfig{});
}

DOCTEST_TEST_CASE(
  "Soak: as above, with real crypto and more iterations" *
  doctest::test_suite("real_stack_fuzz_soak"))
{
  // See NOTE_IS_PRIMARY_RACE (fixture.h) - applies here too.
  if (std::getenv("REAL_STACK_SOAK") == nullptr)
  {
    DOCTEST_MESSAGE(
      "Skipping soak variant - set REAL_STACK_SOAK=1 to run it (real "
      "AES-GCM encryption per transaction, and more iterations, so this is "
      "deliberately not part of the default fast test run)");
    return;
  }

  FuzzConfig cfg;
  cfg.use_real_crypto = true;
  cfg.num_writers = 8;
  cfg.writer_iterations = 500;
  cfg.reelection_iterations = 200;
  run_fuzz(pick_seed(), cfg);
}
