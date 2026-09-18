// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// A transaction which consensus is going to reject must never be published
// to the ledger history. Readers of the history, for instance
// set_root_on_proposals(), take no Store lock, so a transiently appended
// digest would give them a root which is in neither the KV nor the ledger.
//
// Store::commit() checks the transaction's view under version_lock, then
// releases that lock before appending to the history. A rollback can land in
// that window. The guard is the view captured under version_lock, which is
// passed to TxHistory::append_entry() and compared against the history's own
// view under the history lock, dropping the append if they differ.
//
// Interleaving, from PR #8223:
//
// - Tx A passes Store::commit()'s view check under version_lock, which is
//   then released.
// - An election rolls the Store and the ledger history back to seqno 1.
// - A appends its digest to the history, then consensus rejects it.

#include "node/history.h"
#include "view_straddling_common.h"

#include <chrono>

using namespace straddling;

namespace
{
  // A history which pauses once, on the next append_entry() call after it is
  // armed, after the base class has done its work and released its lock. What
  // it has published at that point is exactly what any concurrent reader of
  // the history would see.
  class PausableHistory : public ccf::MerkleTxHistory
  {
    std::mutex lock;
    std::condition_variable cv;
    bool armed = false;
    bool reached = false;
    bool resume = false;

  public:
    using ccf::MerkleTxHistory::MerkleTxHistory;

    void arm()
    {
      std::lock_guard<std::mutex> guard(lock);
      armed = true;
    }

    void append_entry(
      const ccf::crypto::Sha256Hash& digest,
      std::optional<ccf::kv::Term> expected_term_of_next_version =
        std::nullopt) override
    {
      ccf::MerkleTxHistory::append_entry(digest, expected_term_of_next_version);

      std::unique_lock<std::mutex> guard(lock);
      if (armed)
      {
        armed = false;
        reached = true;
        cv.notify_all();
        cv.wait(guard, [this]() { return resume; });
      }
    }

    bool wait_until_reached(std::chrono::milliseconds timeout)
    {
      std::unique_lock<std::mutex> guard(lock);
      return cv.wait_for(guard, timeout, [this]() { return reached; });
    }

    void release()
    {
      {
        std::lock_guard<std::mutex> guard(lock);
        resume = true;
      }
      cv.notify_all();
    }
  };

  struct HistoryFixture : public Fixture
  {
    ccf::crypto::ECKeyPairPtr node_kp = ccf::crypto::make_ec_key_pair();
    std::shared_ptr<PausableHistory> history;

    HistoryFixture()
    {
      history = std::make_shared<PausableHistory>(*store, node_id, *node_kp);
      store->set_history(history);
      start();
    }
  };
}

TEST_CASE(
  "Rolled-back stale transaction is not published to the ledger history" *
  doctest::test_suite("view_straddling_history"))
{
  HistoryFixture fixture;

  const auto [baseline_txid, baseline_root, baseline_term] =
    fixture.history->get_replicated_state_txid_and_root();
  REQUIRE(baseline_txid.seqno == 1);

  INFO("Apply and serialise A at seqno 2 in the initial view");
  const auto stale_txid = fixture.store->next_txid();
  REQUIRE(stale_txid == ccf::TxID(fixture.initial_view, 2));
  auto stale_info = [&]() {
    auto tx = fixture.store->create_reserved_tx(stale_txid);
    tx.rw(fixture.table)->put(1, 2);
    return tx.commit_reserved();
  }();
  REQUIRE(stale_info.success == ccf::kv::CommitResult::SUCCESS);

  INFO("A enters Store::commit, passes its view check, then is descheduled");
  CommitPause commit_pause;
  std::optional<ccf::kv::CommitResult> stale_result;
  std::thread stale_worker([&]() {
    stale_result = fixture.store->commit(
      stale_txid,
      std::make_unique<PausingMovePendingTx>(
        std::move(stale_info), commit_pause),
      false);
  });
  commit_pause.wait_until_paused();

  INFO("Lose leadership and win a later election, rolling back to seqno 1");
  fixture.reelect();
  {
    const auto [rolled_back_txid, rolled_back_root, rolled_back_term] =
      fixture.history->get_replicated_state_txid_and_root();
    REQUIRE(rolled_back_txid.seqno == 1);
    REQUIRE(rolled_back_root == baseline_root);
  }

  INFO("Resume A, and observe the history once its append has completed");
  fixture.history->arm();
  commit_pause.release();
  REQUIRE(fixture.history->wait_until_reached(std::chrono::seconds(5)));
  {
    const auto [observed_txid, observed_root, observed_term] =
      fixture.history->get_replicated_state_txid_and_root();
    CHECK(observed_txid.seqno == 1);
    CHECK(observed_root == baseline_root);
  }
  fixture.history->release();
  stale_worker.join();

  INFO("Consensus rejects A, and history, KV and ledger agree");
  REQUIRE(stale_result.has_value());
  CHECK(stale_result.value() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  {
    const auto [final_txid, final_root, final_term] =
      fixture.history->get_replicated_state_txid_and_root();
    CHECK(final_txid.seqno == 1);
    CHECK(final_root == baseline_root);
  }
  CHECK(fixture.store->current_txid().seqno == 1);
  CHECK(fixture.raft->get_last_idx() == 1);
  CHECK(fixture.raft->ledger->ledger.size() == 1);
}
