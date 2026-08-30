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
//  - One reader thread, continuously polling AFT and TxHistory terms.
//
// All randomness is drawn from a single seed (overridable via the RNG_SEED
// environment variable), logged unconditionally so any CI failure is
// re-runnable with the same seed. A real-OS-thread fuzzer is not
// byte-for-byte replayable purely from a seed - actual thread scheduling
// still varies run to run - so "reproducible" here means the same seed
// reliably exercises the same kind of interleaving, not an identical trace.
//
// The live term invariant reads AFT's monotonic view before and after history.
// Store/history seqnos are compared only after all actors quiesce: Store
// versions can advance and roll back to the same value around a history read,
// so equal before/after samples cannot rule out an ABA false positive.

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
    std::mutex failed_keys_lock;
    std::vector<size_t> failed_keys;

    // Reader actor: continuously checks that history's current term is never
    // ahead of AFT's monotonic view.
    std::thread reader([&]() {
      while (!stop.load())
      {
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
      writers.emplace_back(
        [&fixture, &failed_keys_lock, &failed_keys, &cfg, w, writer_seed]() {
          std::mt19937 rng(writer_seed);
          for (size_t i = 0; i < cfg.writer_iterations; ++i)
          {
            random_delay(rng, cfg.max_writer_delay);
            const auto key = (w * 1'000'000) + i;
            auto tx = fixture.store->create_tx();
            tx.rw(fixture.table)->put(key, i);
            const auto result = tx.commit();
            if (result == ccf::kv::CommitResult::FAIL_NO_REPLICATE)
            {
              std::lock_guard<std::mutex> guard(failed_keys_lock);
              failed_keys.push_back(key);
            }
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
      "Once all actors quiesce, no failed transaction remains visible and "
      "Store, history, chunker, and AFT agree without a healing election");
    for (const auto key : failed_keys)
    {
      DOCTEST_CHECK_FALSE(
        read_value(*fixture.store, fixture.table, key).has_value());
    }
    const auto quiescent_txid = fixture.store->current_txid();
    DOCTEST_CHECK(fixture.history_txid().seqno == quiescent_txid.seqno);
    DOCTEST_CHECK(fixture.raft->get_last_idx() == quiescent_txid.seqno);
    DOCTEST_CHECK(fixture.chunker->current_version() == quiescent_txid.seqno);

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
  run_fuzz(pick_seed(), FuzzConfig{});
}

DOCTEST_TEST_CASE(
  "Soak: as above, with real crypto and more iterations" *
  doctest::test_suite("real_stack_fuzz_soak"))
{
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
