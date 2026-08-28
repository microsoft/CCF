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

  public:
    ReservedWritePendingTx(
      ccf::TxID txid_,
      ccf::kv::Store& store_,
      RealStackTable& table_,
      size_t key_,
      size_t value_) :
      txid(txid_),
      store(store_),
      table(table_),
      key(key_),
      value(value_)
    {}

    ccf::kv::PendingTxInfo call() override
    {
      auto tx = store.create_reserved_tx(txid);
      tx.rw(table)->put(key, value);
      return tx.commit_reserved();
    }
  };
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
      ccf::empty_claims(), nullptr, checkpoint_write_set_observer(checkpoint));
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
    "immediately, with no additional election required (contrast with "
    "NOTE_REJECTED_COMMIT_STALL below, where regaining leadership before "
    "the stale commit lands currently does leave the Store unable to "
    "replicate anything further until another election happens)");
  for (size_t i = 0; i < 3; ++i)
  {
    auto later_tx = fixture.store->create_tx();
    later_tx.rw(fixture.table)->put(i + 10, i + 10);
    DOCTEST_CHECK(later_tx.commit() == ccf::kv::CommitResult::SUCCESS);
    DOCTEST_CHECK(fixture.raft->get_last_idx() == fresh_seqno + i + 1);
  }
}

DOCTEST_TEST_CASE(
  "NOTE_REJECTED_COMMIT_STALL: regaining leadership before a stale-view "
  "commit lands must not permanently stall replication" *
  doctest::test_suite("real_stack_deterministic"))
{
  // NOTE_REJECTED_COMMIT_STALL: as of writing, a transaction rejected here
  // leaves its local write applied to the Store with no corresponding
  // entry ever reaching consensus, and every ordinary transaction
  // committed afterwards keeps succeeding locally while none of them
  // reach consensus either - until a further election restores agreement.
  // The DOCTEST_CHECKs below marked with this tag are expected to fail
  // until that is fixed; the rest of this test still passes.
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
    "term is rejected when it reaches Store::commit()");
  DOCTEST_CHECK(tx.commit() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);

  DOCTEST_INFO(
    "A rejected transaction should not leave a local write behind that "
    "never reaches consensus: the Store should read back exactly as it "
    "did before this transaction was attempted");
  DOCTEST_CHECK(fixture.store->current_txid() == baseline_txid); // NOTE_REJECTED_COMMIT_STALL
  DOCTEST_CHECK(fixture.history_txid() == baseline_txid);

  DOCTEST_INFO(
    "Whatever the Store's state after the rejection above, every "
    "ordinary transaction committed from here on must still reach "
    "consensus - the Store's replicated state must never fall "
    "permanently behind its own local version");
  for (size_t i = 0; i < 3; ++i)
  {
    auto later_tx = fixture.store->create_tx();
    later_tx.rw(fixture.table)->put(i + 1, i + 1);
    DOCTEST_CHECK(later_tx.commit() == ccf::kv::CommitResult::SUCCESS);
    DOCTEST_CHECK( // NOTE_REJECTED_COMMIT_STALL
      fixture.raft->get_last_idx() == fixture.store->current_txid().seqno);
  }

  DOCTEST_INFO(
    "A further election always restores agreement between the Store, "
    "TxHistory, and raft's own record of what has been replicated");
  fixture.reelect();
  auto healed_tx = fixture.store->create_tx();
  healed_tx.rw(fixture.table)->put(0, 2);
  DOCTEST_CHECK(healed_tx.commit() == ccf::kv::CommitResult::SUCCESS);
  DOCTEST_CHECK(
    fixture.raft->get_last_idx() == fixture.store->current_txid().seqno);
  DOCTEST_CHECK(
    fixture.history_txid().seqno == fixture.store->current_txid().seqno);
  DOCTEST_CHECK(fixture.history_term_of_next_version() == fixture.raft->get_view());
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
  //
  // This currently exercises NOTE_IS_PRIMARY_RACE (see
  // RealStackFixture::reelect() in fixture.h). Expect this test to fail
  // occasionally, or to abort the whole process under ThreadSanitizer,
  // until that race is fixed.
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
