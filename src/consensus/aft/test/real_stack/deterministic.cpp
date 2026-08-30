// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "consensus/aft/test/real_stack/fixture.h"

#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
#include <atomic>
#include <doctest/doctest.h>
#include <optional>
#include <random>
#include <thread>

// Deterministic scenarios driven by RealStackFixture, pinned via
// ccf::kv::test::Checkpoint from src/kv/test/interleaving.h.

using namespace ccf::kv::test;

namespace
{
  class CountingConsensusHook : public ccf::kv::ConsensusHook
  {
    std::atomic<size_t>& calls;

  public:
    CountingConsensusHook(std::atomic<size_t>& calls_) : calls(calls_) {}

    void call(ccf::kv::ConfigurableConsensus*) override
    {
      calls++;
    }
  };

  // Directly drives Store::commit()-style application of a write to a
  // specific, pre-reserved TxID - mirroring how a signature transaction
  // fills a slot reserved earlier via next_txid().
  class ReservedWritePendingTx : public ccf::kv::PendingTx
  {
    ccf::TxID txid;
    ccf::kv::Store& store;
    RealStackTable& table;
    size_t key;
    size_t value;
    Checkpoint* before_reserved_prepare;

  public:
    ReservedWritePendingTx(
      ccf::TxID txid_,
      ccf::kv::Store& store_,
      RealStackTable& table_,
      size_t key_,
      size_t value_,
      Checkpoint* before_reserved_prepare_ = nullptr) :
      txid(txid_),
      store(store_),
      table(table_),
      key(key_),
      value(value_),
      before_reserved_prepare(before_reserved_prepare_)
    {}

    ccf::kv::PendingTxInfo call() override
    {
      auto tx = store.create_reserved_tx(txid);
      tx.rw(table)->put(key, value);
      if (before_reserved_prepare != nullptr)
      {
        return tx.commit_reserved(
          checkpoint_post_apply_observer(*before_reserved_prepare));
      }
      return tx.commit_reserved();
    }
  };

  enum class HistoryAppendPause
  {
    Before,
    After
  };

  void check_election_at_history_append(
    HistoryAppendPause pause,
    bool regain_leadership,
    bool use_real_crypto = false)
  {
    RealStackFixture fixture(use_real_crypto);
    const auto baseline_txid = fixture.commit_signature();
    const auto [baseline_history_txid, baseline_root, baseline_term] =
      fixture.history->get_replicated_state_txid_and_root();
    (void)baseline_term;

    Checkpoint checkpoint("history append");
    if (pause == HistoryAppendPause::Before)
    {
      fixture.history->pause_before_next_append_entry(checkpoint);
    }
    else
    {
      fixture.history->pause_after_next_append_entry(checkpoint);
    }

    constexpr size_t stale_key = 5000;
    auto stale_tx = fixture.store->create_tx();
    stale_tx.rw(fixture.table)->put(stale_key, stale_key);

    std::optional<ccf::kv::CommitResult> stale_result;
    std::thread stale_worker([&]() { stale_result = stale_tx.commit(); });
    checkpoint.wait_until_paused();

    try
    {
      if (regain_leadership)
      {
        fixture.reelect();
      }
      else
      {
        fixture.step_down();
      }
    }
    catch (...)
    {
      checkpoint.release();
      stale_worker.join();
      throw;
    }

    checkpoint.release();
    stale_worker.join();

    DOCTEST_REQUIRE(stale_result.has_value());
    DOCTEST_CHECK(
      stale_result.value() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
    DOCTEST_CHECK(fixture.store->current_txid() == baseline_txid);
    DOCTEST_CHECK_FALSE(
      read_value(*fixture.store, fixture.table, stale_key).has_value());

    const auto [history_txid, history_root, history_term] =
      fixture.history->get_replicated_state_txid_and_root();
    DOCTEST_CHECK(history_txid == baseline_history_txid);
    DOCTEST_CHECK(history_root == baseline_root);
    DOCTEST_CHECK(history_term == fixture.raft->get_view());
    DOCTEST_CHECK(fixture.raft->get_last_idx() == baseline_txid.seqno);
    DOCTEST_CHECK(fixture.chunker->current_version() == baseline_txid.seqno);

    if (!regain_leadership)
    {
      fixture.raft->force_become_primary();
    }

    auto fresh_tx = fixture.store->create_tx();
    fresh_tx.rw(fixture.table)->put(stale_key, stale_key + 1);
    DOCTEST_REQUIRE(fresh_tx.commit() == ccf::kv::CommitResult::SUCCESS);
    DOCTEST_CHECK(
      fixture.raft->get_last_idx() == fixture.store->current_txid().seqno);
    DOCTEST_CHECK(
      fixture.history_txid().seqno == fixture.store->current_txid().seqno);
    DOCTEST_CHECK(
      read_value(*fixture.store, fixture.table, stale_key) == stale_key + 1);
  }

  void check_rollback_sensitive_tx_flag(
    ccf::kv::CommittableTx::TxFlag flag,
    const std::function<void(RealStackFixture&, const ccf::TxID&)>&
      check_cleared)
  {
    RealStackFixture fixture;
    const auto baseline_txid = fixture.commit_signature();

    Checkpoint checkpoint("after local application");
    constexpr size_t stale_key = 8000;
    auto stale_tx = fixture.store->create_tx();
    stale_tx.set_tx_flag(flag);
    stale_tx.rw(fixture.table)->put(stale_key, stale_key);

    std::optional<ccf::kv::CommitResult> stale_result;
    std::thread stale_worker([&]() {
      stale_result = stale_tx.commit(
        ccf::empty_claims(),
        nullptr,
        checkpoint_post_apply_observer(checkpoint));
    });
    checkpoint.wait_until_paused();

    try
    {
      fixture.reelect();
    }
    catch (...)
    {
      checkpoint.release();
      stale_worker.join();
      throw;
    }

    checkpoint.release();
    stale_worker.join();

    DOCTEST_REQUIRE(stale_result.has_value());
    DOCTEST_CHECK(
      stale_result.value() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
    DOCTEST_CHECK(fixture.store->current_txid() == baseline_txid);
    DOCTEST_CHECK_FALSE(
      read_value(*fixture.store, fixture.table, stale_key).has_value());
    check_cleared(fixture, baseline_txid);
  }
}

DOCTEST_TEST_CASE(
  "Long-lived transaction is rolled back after a real leadership loss, and "
  "TxHistory follows the Store exactly" *
  doctest::test_suite("real_stack_deterministic"))
{
  RealStackFixture fixture;
  const auto baseline_txid = fixture.commit_signature();

  DOCTEST_INFO("Start applying a local transaction in the initial view");
  auto stale_tx = fixture.store->create_tx();
  stale_tx.rw(fixture.table)->put(1, 2);

  Checkpoint checkpoint("stale_tx write-set observer");
  std::optional<ccf::kv::CommitResult> stale_result;
  std::thread stale_worker([&]() {
    stale_result = stale_tx.commit(
      ccf::empty_claims(), checkpoint_write_set_observer(checkpoint));
  });
  checkpoint.wait_until_paused();
  // stale_worker is now parked inside checkpoint.pause(), and must be
  // released and joined before this scope exits by any path - including a
  // failed DOCTEST_REQUIRE below, which throws to unwind the test case.
  // Destroying a still-joinable std::thread calls std::terminate(),
  // crashing the whole test binary instead of cleanly reporting a single
  // test failure, so any exception here is caught, the worker is
  // released/joined, and then rethrown.
  try
  {
    DOCTEST_REQUIRE(
      stale_tx.get_txid() ==
      ccf::TxID(fixture.initial_view, baseline_txid.seqno + 1));
  }
  catch (...)
  {
    checkpoint.release();
    stale_worker.join();
    throw;
  }

  DOCTEST_INFO("Lose leadership after the transaction has an assigned TxID");
  fixture.step_down();

  DOCTEST_INFO("Aft rejects the transaction and rolls the Store back");
  checkpoint.release();
  stale_worker.join();
  DOCTEST_REQUIRE(stale_result.has_value());
  DOCTEST_CHECK(
    stale_result.value() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  DOCTEST_CHECK(fixture.store->current_txid() == baseline_txid);
  DOCTEST_CHECK(fixture.history_txid() == baseline_txid);
  DOCTEST_CHECK_FALSE(read_value(*fixture.store, fixture.table, 1).has_value());

  DOCTEST_INFO(
    "Win a later election and replicate the next transaction normally");
  fixture.raft->force_become_primary();
  const auto fresh_view = fixture.raft->get_view();
  auto fresh_tx = fixture.store->create_tx();
  fresh_tx.rw(fixture.table)->put(2, 3);
  DOCTEST_REQUIRE(fresh_tx.commit() == ccf::kv::CommitResult::SUCCESS);
  // Note: history_txid().view is not expected to match fresh_view here -
  // see the comment on RealStackFixture::history_txid() for why an ordinary
  // in-term commit does not refresh it. Seqno agreement and
  // history_term_of_next_version() are checked instead.
  const auto fresh_seqno = baseline_txid.seqno + 1;
  DOCTEST_CHECK(
    fixture.store->current_txid() == ccf::TxID(fresh_view, fresh_seqno));
  DOCTEST_CHECK(fixture.history_txid().seqno == fresh_seqno);
  DOCTEST_CHECK(fixture.history_term_of_next_version() == fresh_view);
  DOCTEST_CHECK(read_value(*fixture.store, fixture.table, 2) == 3);

  DOCTEST_INFO(
    "Rejecting the stale transaction did not leave anything behind to "
    "clean up: every further ordinary commit keeps reaching consensus "
    "immediately, with no additional election required");
  for (size_t i = 0; i < 3; ++i)
  {
    auto later_tx = fixture.store->create_tx();
    later_tx.rw(fixture.table)->put(i + 10, i + 10);
    DOCTEST_CHECK(later_tx.commit() == ccf::kv::CommitResult::SUCCESS);
    DOCTEST_CHECK(fixture.raft->get_last_idx() == fresh_seqno + i + 1);
  }
}

DOCTEST_TEST_CASE(
  "A stale-view commit that lands while merely a pre-vote candidate rolls "
  "back cleanly too, exactly like the follower case" *
  doctest::test_suite("real_stack_deterministic"))
{
  RealStackFixture fixture;
  const auto baseline_txid = fixture.commit_signature();

  auto tx = fixture.store->create_tx();
  tx.rw(fixture.table)->put(0, 1);

  DOCTEST_INFO(
    "Step down to follower, then add a second (never-responding) node to "
    "the configuration and let the election timeout elapse, so this node "
    "becomes a pre-vote candidate on its own - still not primary, exactly "
    "like the follower case above, rather than having regained "
    "leadership");
  fixture.step_down();
  ccf::kv::Configuration::Nodes two_node_config;
  two_node_config.try_emplace(fixture.node_id);
  two_node_config.try_emplace(ccf::NodeId("NeverRespondingSecondNode"));
  fixture.raft->add_configuration(
    fixture.raft->get_last_idx(), two_node_config);
  fixture.raft->periodic(std::chrono::milliseconds(200));
  DOCTEST_REQUIRE_FALSE(fixture.raft->is_primary());

  DOCTEST_CHECK(tx.commit() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  DOCTEST_CHECK(fixture.store->current_txid() == baseline_txid);
  DOCTEST_CHECK(fixture.history_txid() == baseline_txid);

  DOCTEST_INFO(
    "As with the follower case, nothing was left behind to clean up: "
    "winning the next election lets ordinary commits reach consensus "
    "immediately, with no further election needed");
  fixture.raft->force_become_primary();
  auto healed_tx = fixture.store->create_tx();
  healed_tx.rw(fixture.table)->put(0, 2);
  DOCTEST_CHECK(healed_tx.commit() == ccf::kv::CommitResult::SUCCESS);
  DOCTEST_CHECK(healed_tx.get_txid()->seqno == baseline_txid.seqno + 1);
  DOCTEST_CHECK(fixture.raft->get_last_idx() == baseline_txid.seqno + 1);
}

DOCTEST_TEST_CASE(
  "An ordinary commit immediately after a real election keeps Store and "
  "TxHistory in agreement" *
  doctest::test_suite("real_stack_deterministic"))
{
  RealStackFixture fixture;
  const auto baseline_txid = fixture.commit_signature();

  DOCTEST_INFO("Win a later election with no prior in-flight transaction");
  const auto reelection_view = fixture.reelect();
  DOCTEST_CHECK(fixture.store->current_txid() == baseline_txid);
  DOCTEST_CHECK(fixture.history_txid() == baseline_txid);

  DOCTEST_INFO(
    "A transaction reading and writing entirely in the new view commits "
    "cleanly");
  auto tx = fixture.store->create_tx();
  tx.rw(fixture.table)->put(0, 1);
  DOCTEST_REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  const auto committed_seqno = baseline_txid.seqno + 1;
  DOCTEST_CHECK(tx.get_txid() == ccf::TxID(reelection_view, committed_seqno));
  DOCTEST_CHECK(fixture.store->current_txid().seqno == committed_seqno);
  DOCTEST_CHECK(fixture.history_txid().seqno == committed_seqno);
  DOCTEST_CHECK(fixture.history_term_of_next_version() == reelection_view);
  DOCTEST_CHECK(read_value(*fixture.store, fixture.table, 0) == 1);
}

// Store::commit() can batch several already-applied transactions into a
// single call to consensus, rather than replicating each one individually.
// The next two test cases check what happens when a real election lands
// partway through such a batch: TxHistory must end up exactly where the
// Store does, never ahead of it.

DOCTEST_TEST_CASE(
  "Concurrent rollback triggered by a real election during an in-flight "
  "commit batch does not leave TxHistory ahead of the Store's own "
  "replicated state" *
  doctest::test_suite("real_stack_deterministic"))
{
  // The election lands after the first entry of the batch has been applied,
  // but before the second has - so the rollback below runs against a batch
  // that is genuinely partway through, not one that never started.
  RealStackFixture fixture;
  const auto baseline_txid = fixture.commit_signature();
  const ccf::TxID first_txid(fixture.initial_view, baseline_txid.seqno + 1);
  const ccf::TxID second_txid(fixture.initial_view, baseline_txid.seqno + 2);

  DOCTEST_INFO(
    "Reserve the first slot as a hole, and park the second entry behind it "
    "(wrapped so it pauses on its own local application) - neither can be "
    "replicated while the hole remains");
  DOCTEST_REQUIRE(fixture.store->next_txid() == first_txid);
  Checkpoint checkpoint("second entry's local application");
  DOCTEST_REQUIRE(
    fixture.store->commit(
      second_txid,
      std::make_unique<PausingPendingTx>(
        std::make_unique<ReservedWritePendingTx>(
          second_txid, *fixture.store, fixture.table, 3, 4),
        checkpoint),
      false) == ccf::kv::CommitResult::SUCCESS);
  // Nothing has been sent to consensus yet - the hole is still missing, so
  // history cannot have moved past the baseline, and the pause above was
  // never reached (this call returned before its batching loop, since the
  // hole made it non-contiguous).
  DOCTEST_CHECK(fixture.history_txid() == baseline_txid);

  DOCTEST_INFO(
    "Fill the hole. This bundles [first, second] into one Store::commit() "
    "batch: the first entry is applied and recorded in history for real, "
    "then the second (already-queued) entry pauses on its own local "
    "application, before it is recorded");
  std::optional<ccf::kv::CommitResult> result;
  std::thread worker([&]() {
    result = fixture.store->commit(
      first_txid,
      std::make_unique<ReservedWritePendingTx>(
        first_txid, *fixture.store, fixture.table, 1, 2),
      false);
  });
  checkpoint.wait_until_paused();

  DOCTEST_INFO(
    "Concurrently win a real election, while the worker above is still "
    "paused mid-commit");
  fixture.reelect();
  DOCTEST_CHECK(fixture.store->current_txid() == baseline_txid);

  checkpoint.release();
  worker.join();

  DOCTEST_REQUIRE(result.has_value());
  DOCTEST_INFO(
    "Store::commit() correctly refuses to advance its own replicated state "
    "past the rollback");
  DOCTEST_CHECK(result.value() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  DOCTEST_CHECK(fixture.store->current_txid() == baseline_txid);

  DOCTEST_INFO(
    "TxHistory ends up back at the baseline too, discarding anything it "
    "recorded before the rollback and never recording anything from "
    "after it");
  DOCTEST_CHECK(fixture.history_txid() == baseline_txid);
  DOCTEST_CHECK(fixture.chunker->current_version() == baseline_txid.seqno);

  auto fresh_tx = fixture.store->create_tx();
  fresh_tx.rw(fixture.table)->put(5, 6);
  DOCTEST_REQUIRE(fresh_tx.commit() == ccf::kv::CommitResult::SUCCESS);
  DOCTEST_CHECK(
    fixture.raft->get_last_idx() == fixture.store->current_txid().seqno);
  DOCTEST_CHECK(
    fixture.history_txid().seqno == fixture.store->current_txid().seqno);
  DOCTEST_CHECK(
    fixture.chunker->current_version() == fixture.store->current_txid().seqno);
}

DOCTEST_TEST_CASE(
  "Fuzz: repeated real elections against a busy writer keep TxHistory "
  "consistent with the Store" *
  doctest::test_suite("real_stack_deterministic"))
{
  // Broader, randomised complement to the pinned test above. One thread
  // continually commits new ordinary transactions (so Store::commit()'s
  // batching loop is usually short, but with enough of them in flight to
  // create many small windows for a race), while another thread repeatedly
  // wins a fresh real election - mimicking a raft node that keeps losing and
  // regaining leadership, discarding all of its own unreplicated writes
  // every time. Because no further signature is emitted during the fuzzing,
  // the one committed at the start remains a permanently-safe rollback
  // target throughout (Store::commit() can never let last_replicated fall
  // below a seqno it has itself successfully replicated), so the final
  // state is fully deterministic regardless of how the two threads
  // interleaved.
  RealStackFixture fixture;
  const auto baseline_txid = fixture.commit_signature();

  constexpr size_t reelection_iterations = 300;
  std::atomic<bool> stop{false};

  std::thread writer([&]() {
    size_t i = 0;
    while (!stop)
    {
      auto tx = fixture.store->create_tx();
      tx.rw(fixture.table)->put(i, i);
      // Any result is acceptable here - conflicts and rollback-induced
      // failures are expected and simply retried with a fresh transaction.
      tx.commit();
      i++;
    }
  });

  std::thread election_churn([&]() {
    std::mt19937 rng(42);
    for (size_t i = 0; i < reelection_iterations; ++i)
    {
      random_delay(rng, std::chrono::microseconds(200));
      fixture.reelect();
    }
    stop = true;
  });

  writer.join();
  election_churn.join();

  DOCTEST_INFO(
    "After all concurrent activity has stopped, one final, fully "
    "deterministic election settles the Store at the permanently-safe "
    "baseline used throughout this fuzz run");
  fixture.reelect();

  const auto final_txid = fixture.store->current_txid();
  DOCTEST_CHECK(final_txid == baseline_txid);
  DOCTEST_INFO(
    "TxHistory's own record of what has been replicated must exactly match "
    "this final, deterministic state - never ahead (which would mean "
    "history recorded entries that were actually rolled back or never "
    "truly committed) and never behind");
  DOCTEST_CHECK(fixture.history_txid() == final_txid);
}

DOCTEST_TEST_CASE(
  "Regaining leadership before a stale-view commit lands does not stall "
  "replication" *
  doctest::test_suite("real_stack_deterministic"))
{
  RealStackFixture fixture;
  const auto baseline_txid = fixture.commit_signature();

  DOCTEST_INFO(
    "Read state (fixing this transaction's commit view) in the initial "
    "view");
  auto tx = fixture.store->create_tx();
  tx.rw(fixture.table)->put(0, 1);

  DOCTEST_INFO("Win a later election before assigning the transaction a TxID");
  fixture.reelect();
  DOCTEST_CHECK(fixture.store->current_txid() == baseline_txid);
  DOCTEST_CHECK(fixture.history_txid() == baseline_txid);

  DOCTEST_INFO(
    "A transaction whose commit view was fixed by a read in a now-stale "
    "term is rejected before its writes are applied");
  DOCTEST_REQUIRE(tx.commit() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);

  DOCTEST_INFO(
    "A rejected transaction should not leave a local write behind that "
    "never reaches consensus: the Store should read back exactly as it "
    "did before this transaction was attempted");
  DOCTEST_CHECK(fixture.store->current_txid() == baseline_txid);
  DOCTEST_CHECK(fixture.history_txid() == baseline_txid);
  DOCTEST_CHECK_FALSE(read_value(*fixture.store, fixture.table, 0).has_value());

  DOCTEST_INFO(
    "Whatever the Store's state after the rejection above, every "
    "ordinary transaction committed from here on must still reach "
    "consensus - the Store's replicated state must never fall "
    "permanently behind its own local version");
  for (size_t i = 0; i < 3; ++i)
  {
    auto later_tx = fixture.store->create_tx();
    later_tx.rw(fixture.table)->put(i + 1, i + 1);
    DOCTEST_REQUIRE(later_tx.commit() == ccf::kv::CommitResult::SUCCESS);
    DOCTEST_CHECK(
      fixture.raft->get_last_idx() == fixture.store->current_txid().seqno);
  }

  DOCTEST_CHECK(
    fixture.history_txid().seqno == fixture.store->current_txid().seqno);
  DOCTEST_CHECK(
    fixture.history_term_of_next_version() == fixture.raft->get_view());
}

DOCTEST_TEST_CASE(
  "Late stale-view rejection removes dynamic maps and suppresses consensus "
  "hooks" *
  doctest::test_suite("real_stack_deterministic"))
{
  RealStackFixture fixture;
  const auto baseline_txid = fixture.commit_signature();
  constexpr auto dynamic_map_name = "public:dynamic";

  std::atomic<size_t> hook_calls = 0;
  fixture.store->set_map_hook(
    fixture.table.get_name(),
    fixture.table.wrap_map_hook(
      [&hook_calls](ccf::kv::Version, const RealStackTable::Write&) {
        return std::make_unique<CountingConsensusHook>(hook_calls);
      }));

  Checkpoint checkpoint("stale write set");
  auto stale_tx = fixture.store->create_tx();
  stale_tx.rw(fixture.table)->put(9000, 9000);
  stale_tx.rw<RealStackTable>(dynamic_map_name)->put(1, 1);
  std::optional<ccf::kv::CommitResult> stale_result;
  std::thread stale_worker([&]() {
    stale_result = stale_tx.commit(
      ccf::empty_claims(), checkpoint_write_set_observer(checkpoint));
  });
  checkpoint.wait_until_paused();

  try
  {
    fixture.reelect();
  }
  catch (...)
  {
    checkpoint.release();
    stale_worker.join();
    throw;
  }

  checkpoint.release();
  stale_worker.join();

  DOCTEST_REQUIRE(stale_result.has_value());
  DOCTEST_CHECK(
    stale_result.value() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  DOCTEST_CHECK(fixture.store->current_txid() == baseline_txid);
  DOCTEST_CHECK(
    fixture.store->get_map(
      fixture.store->current_version(), dynamic_map_name) == nullptr);
  DOCTEST_CHECK(hook_calls == 0);

  auto fresh_tx = fixture.store->create_tx();
  fresh_tx.rw(fixture.table)->put(9001, 9001);
  fresh_tx.rw<RealStackTable>(dynamic_map_name)->put(2, 2);
  DOCTEST_REQUIRE(fresh_tx.commit() == ccf::kv::CommitResult::SUCCESS);
  DOCTEST_CHECK(hook_calls == 1);
}

DOCTEST_TEST_CASE(
  "Elections around history append leave no stale history or replication "
  "gap" *
  doctest::test_suite("real_stack_deterministic"))
{
  DOCTEST_SUBCASE("Rollback and re-election complete before history append")
  {
    check_election_at_history_append(HistoryAppendPause::Before, true);
  }

  DOCTEST_SUBCASE("Step-down completes before history append")
  {
    check_election_at_history_append(HistoryAppendPause::Before, false);
  }

  DOCTEST_SUBCASE("Rollback and re-election complete after history append")
  {
    check_election_at_history_append(HistoryAppendPause::After, true);
  }

  DOCTEST_SUBCASE("Step-down completes after history append")
  {
    check_election_at_history_append(HistoryAppendPause::After, false);
  }

  DOCTEST_SUBCASE("Real encryption before history append")
  {
    check_election_at_history_append(HistoryAppendPause::Before, true, true);
  }

  DOCTEST_SUBCASE("Real encryption after history append")
  {
    check_election_at_history_append(HistoryAppendPause::After, true, true);
  }
}

DOCTEST_TEST_CASE(
  "Rejecting an old-term batch does not erase a newer transaction that has "
  "already applied its writes" *
  doctest::test_suite("real_stack_deterministic"))
{
  RealStackFixture fixture;
  const auto baseline_txid = fixture.commit_signature();

  Checkpoint stale_history_checkpoint("stale history append");
  fixture.history->pause_before_next_append_entry(stale_history_checkpoint);

  constexpr size_t stale_key = 6000;
  auto stale_tx = fixture.store->create_tx();
  stale_tx.rw(fixture.table)->put(stale_key, stale_key);
  std::optional<ccf::kv::CommitResult> stale_result;
  std::thread stale_worker([&]() { stale_result = stale_tx.commit(); });
  stale_history_checkpoint.wait_until_paused();

  try
  {
    fixture.reelect();
  }
  catch (...)
  {
    stale_history_checkpoint.release();
    stale_worker.join();
    throw;
  }

  Checkpoint fresh_write_set_checkpoint("fresh write set");
  constexpr size_t fresh_key = 6001;
  auto fresh_tx = fixture.store->create_tx();
  fresh_tx.rw(fixture.table)->put(fresh_key, fresh_key);
  std::optional<ccf::kv::CommitResult> fresh_result;
  std::thread fresh_worker([&]() {
    fresh_result = fresh_tx.commit(
      ccf::empty_claims(),
      checkpoint_write_set_observer(fresh_write_set_checkpoint));
  });
  fresh_write_set_checkpoint.wait_until_paused();

  stale_history_checkpoint.release();
  stale_worker.join();
  fresh_write_set_checkpoint.release();
  fresh_worker.join();

  DOCTEST_REQUIRE(stale_result.has_value());
  DOCTEST_CHECK(
    stale_result.value() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  DOCTEST_REQUIRE(fresh_result.has_value());
  DOCTEST_CHECK(fresh_result.value() == ccf::kv::CommitResult::SUCCESS);
  DOCTEST_CHECK_FALSE(
    read_value(*fixture.store, fixture.table, stale_key).has_value());
  DOCTEST_CHECK(
    read_value(*fixture.store, fixture.table, fresh_key) == fresh_key);
  DOCTEST_CHECK(
    fixture.store->current_txid() ==
    ccf::TxID(fixture.raft->get_view(), baseline_txid.seqno + 1));
  DOCTEST_CHECK(
    fixture.raft->get_last_idx() == fixture.store->current_txid().seqno);
  DOCTEST_CHECK(
    fixture.history_txid().seqno == fixture.store->current_txid().seqno);
  DOCTEST_CHECK(
    fixture.chunker->current_version() == fixture.store->current_txid().seqno);
}

DOCTEST_TEST_CASE(
  "An election after chunk metadata append rolls every component back" *
  doctest::test_suite("real_stack_deterministic"))
{
  RealStackFixture fixture;
  const auto baseline_txid = fixture.commit_signature();
  const auto baseline_root = fixture.history->get_replicated_state_root();

  Checkpoint checkpoint("chunk metadata append");
  fixture.chunker->pause_after_next_append_entry_size(checkpoint);

  constexpr size_t stale_key = 7000;
  auto stale_tx = fixture.store->create_tx();
  stale_tx.rw(fixture.table)->put(stale_key, stale_key);
  std::optional<ccf::kv::CommitResult> stale_result;
  std::thread stale_worker([&]() { stale_result = stale_tx.commit(); });
  checkpoint.wait_until_paused();

  try
  {
    fixture.step_down();
  }
  catch (...)
  {
    checkpoint.release();
    stale_worker.join();
    throw;
  }

  checkpoint.release();
  stale_worker.join();

  DOCTEST_REQUIRE(stale_result.has_value());
  DOCTEST_CHECK(
    stale_result.value() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  DOCTEST_CHECK(fixture.store->current_txid() == baseline_txid);
  DOCTEST_CHECK(fixture.history_txid() == baseline_txid);
  DOCTEST_CHECK(fixture.history->get_replicated_state_root() == baseline_root);
  DOCTEST_CHECK(fixture.chunker->current_version() == baseline_txid.seqno);
  DOCTEST_CHECK(fixture.raft->get_last_idx() == baseline_txid.seqno);
  DOCTEST_CHECK_FALSE(
    read_value(*fixture.store, fixture.table, stale_key).has_value());
}

DOCTEST_TEST_CASE(
  "An election after AFT accepts a batch prevents stale Store bookkeeping" *
  doctest::test_suite("real_stack_deterministic"))
{
  RealStackFixture fixture;
  const auto baseline_txid = fixture.commit_signature();
  const auto baseline_root = fixture.history->get_replicated_state_root();

  Checkpoint checkpoint("AFT replicate");
  fixture.raft->pause_after_next_replicate_call(checkpoint);

  constexpr size_t rolled_back_key = 7001;
  auto tx = fixture.store->create_tx();
  tx.rw(fixture.table)->put(rolled_back_key, rolled_back_key);
  std::optional<ccf::kv::CommitResult> result;
  std::thread worker([&]() { result = tx.commit(); });
  checkpoint.wait_until_paused();

  try
  {
    fixture.reelect();
  }
  catch (...)
  {
    checkpoint.release();
    worker.join();
    throw;
  }

  checkpoint.release();
  worker.join();

  DOCTEST_REQUIRE(result.has_value());
  DOCTEST_CHECK(result.value() == ccf::kv::CommitResult::SUCCESS);
  DOCTEST_CHECK(fixture.store->current_txid() == baseline_txid);
  DOCTEST_CHECK(fixture.history_txid() == baseline_txid);
  DOCTEST_CHECK(fixture.history->get_replicated_state_root() == baseline_root);
  DOCTEST_CHECK(fixture.chunker->current_version() == baseline_txid.seqno);
  DOCTEST_CHECK(fixture.raft->get_last_idx() == baseline_txid.seqno);
  DOCTEST_CHECK_FALSE(
    read_value(*fixture.store, fixture.table, rolled_back_key).has_value());

  auto fresh_tx = fixture.store->create_tx();
  fresh_tx.rw(fixture.table)->put(rolled_back_key, rolled_back_key + 1);
  DOCTEST_REQUIRE(fresh_tx.commit() == ccf::kv::CommitResult::SUCCESS);
  DOCTEST_CHECK(fixture.store->current_txid().seqno == baseline_txid.seqno + 1);
  DOCTEST_CHECK(
    fixture.raft->get_last_idx() == fixture.store->current_txid().seqno);
  DOCTEST_CHECK(
    fixture.history_txid().seqno == fixture.store->current_txid().seqno);
  DOCTEST_CHECK(
    fixture.chunker->current_version() == fixture.store->current_txid().seqno);
}

DOCTEST_TEST_CASE(
  "Rollback-sensitive transaction flags are not restored after an election" *
  doctest::test_suite("real_stack_deterministic"))
{
  DOCTEST_SUBCASE("Forced ledger chunk")
  {
    check_rollback_sensitive_tx_flag(
      ccf::kv::CommittableTx::TxFlag::LEDGER_CHUNK_AT_NEXT_SIGNATURE,
      [](RealStackFixture& fixture, const ccf::TxID& baseline_txid) {
        DOCTEST_CHECK_FALSE(
          fixture.chunker->is_chunk_end_requested(baseline_txid.seqno + 1));
      });
  }

  DOCTEST_SUBCASE("Snapshot at next signature")
  {
    check_rollback_sensitive_tx_flag(
      ccf::kv::CommittableTx::TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE,
      [](RealStackFixture& fixture, const ccf::TxID&) {
        DOCTEST_CHECK_FALSE(fixture.store->flag_enabled(
          ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE));
      });
  }
}

DOCTEST_TEST_CASE(
  "A read-only transaction still arms a requested snapshot" *
  doctest::test_suite("real_stack_deterministic"))
{
  RealStackFixture fixture;
  fixture.commit_signature();
  DOCTEST_REQUIRE_FALSE(fixture.store->flag_enabled(
    ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE));

  const auto txid_before = fixture.store->current_txid();
  auto tx = fixture.store->create_tx();
  tx.set_tx_flag(ccf::kv::CommittableTx::TxFlag::SNAPSHOT_AT_NEXT_SIGNATURE);
  // Acquire a handle without writing, so this transaction is assigned no
  // version but still carries the flag.
  tx.rw(fixture.table)->get(0);
  DOCTEST_REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  DOCTEST_REQUIRE(fixture.store->current_txid() == txid_before);

  DOCTEST_CHECK(fixture.store->flag_enabled(
    ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE));
}

DOCTEST_TEST_CASE(
  "Ledger chunk requests remain attached to their transaction version" *
  doctest::test_suite("real_stack_deterministic"))
{
  RealStackFixture fixture;
  fixture.commit_signature();

  Checkpoint flagged_checkpoint("flagged transaction after apply");
  auto flagged_tx = fixture.store->create_tx();
  flagged_tx.set_tx_flag(
    ccf::kv::CommittableTx::TxFlag::LEDGER_CHUNK_AT_NEXT_SIGNATURE);
  flagged_tx.rw(fixture.table)->put(8100, 8100);
  std::optional<ccf::kv::CommitResult> flagged_result;
  std::thread flagged_worker([&]() {
    flagged_result = flagged_tx.commit(
      ccf::empty_claims(),
      nullptr,
      checkpoint_post_apply_observer(flagged_checkpoint));
  });
  flagged_checkpoint.wait_until_paused();
  const auto flagged_txid = flagged_tx.get_txid().value();

  Checkpoint later_checkpoint("later transaction after apply");
  auto later_tx = fixture.store->create_tx();
  later_tx.rw(fixture.table)->put(8101, 8101);
  std::optional<ccf::kv::CommitResult> later_result;
  std::thread later_worker([&]() {
    later_result = later_tx.commit(
      ccf::empty_claims(),
      nullptr,
      checkpoint_post_apply_observer(later_checkpoint));
  });
  later_checkpoint.wait_until_paused();
  const auto later_txid = later_tx.get_txid().value();

  flagged_checkpoint.release();
  flagged_worker.join();
  later_checkpoint.release();
  later_worker.join();

  DOCTEST_REQUIRE(flagged_result.has_value());
  DOCTEST_CHECK(flagged_result.value() == ccf::kv::CommitResult::SUCCESS);
  DOCTEST_REQUIRE(later_result.has_value());
  DOCTEST_CHECK(later_result.value() == ccf::kv::CommitResult::SUCCESS);
  DOCTEST_CHECK(flagged_txid.seqno < later_txid.seqno);
  DOCTEST_CHECK(fixture.chunker->has_forced_chunk(flagged_txid.seqno));
  DOCTEST_CHECK_FALSE(fixture.chunker->has_forced_chunk(later_txid.seqno));
}

DOCTEST_TEST_CASE(
  "Rollback during reserved chunk production leaves no stale chunk marker" *
  doctest::test_suite("real_stack_deterministic"))
{
  RealStackFixture fixture;
  fixture.install_inspectable_snapshotter();
  const auto baseline_txid = fixture.commit_signature();
  const auto reserved_txid = fixture.store->next_txid();
  fixture.chunker->force_end_of_chunk(baseline_txid.seqno);

  Checkpoint checkpoint("before reserved side effects");
  std::optional<ccf::kv::CommitResult> result;
  std::thread worker([&]() {
    result = fixture.store->commit(
      reserved_txid,
      std::make_unique<ReservedWritePendingTx>(
        reserved_txid, *fixture.store, fixture.table, 7002, 7002, &checkpoint),
      true);
  });
  checkpoint.wait_until_paused();

  try
  {
    fixture.reelect();
  }
  catch (...)
  {
    checkpoint.release();
    worker.join();
    throw;
  }

  checkpoint.release();
  worker.join();

  DOCTEST_REQUIRE(result.has_value());
  DOCTEST_CHECK(result.value() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  DOCTEST_CHECK(fixture.store->current_txid() == baseline_txid);
  DOCTEST_CHECK(fixture.history_txid() == baseline_txid);
  DOCTEST_CHECK(fixture.chunker->current_version() == baseline_txid.seqno);
  DOCTEST_CHECK_FALSE(fixture.chunker->has_chunk_end(reserved_txid.seqno));
  DOCTEST_CHECK_FALSE(fixture.snapshotter->has_recorded(reserved_txid.seqno));
}
