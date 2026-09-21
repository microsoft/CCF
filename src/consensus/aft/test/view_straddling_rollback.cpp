// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// A rollback triggered by consensus rejecting one transaction must not
// discard the local application of another transaction which consensus is
// still going to accept. Otherwise the second transaction reaches the ledger
// but not the KV, and the Store's version falls behind Raft's last index, so
// the next transaction reuses a seqno and is silently never replicated.
//
// Raft::replicate() therefore must not roll back on a term mismatch: by the
// time a stale entry is rejected, the election which moved the term has
// already rolled back everything from the old term, and anything applied
// since belongs to the current term.
//
// Interleaving, from review of PR #8209 (cjen1-msft, src/consensus/aft/raft.h):
//
// - Tx A is applied locally in view V and given TxID V.2. It enters
//   Store::commit(), passes the view check, and is descheduled before it
//   reaches consensus.
// - An election happens. The node wins in view W > V, and become_leader()
//   rolls the Store back past A, to seqno 1.
// - Tx B is applied locally in view W and given TxID W.2. It has not yet
//   entered Store::commit().
// - A continues. Consensus rejects it. If that rejection rolls the Store
//   back to Raft's last_idx (1), it discards B's local application as well.
// - B enters Store::commit(), passes the view check (W == W), and is
//   replicated. It is in the ledger, but no longer in the KV.

#include "view_straddling_common.h"

#include <format>

using namespace straddling;

namespace
{
  std::string describe(Fixture& fixture)
  {
    const auto value = read_value(*fixture.store, fixture.table, 2);
    return std::format(
      "store txid {}, key 2 -> {}, raft last_idx {}, ledger entries {}",
      fixture.store->current_txid().to_str(),
      value.has_value() ? std::to_string(value.value()) : "absent",
      fixture.raft->get_last_idx(),
      fixture.raft->ledger->ledger.size());
  }
}

TEST_CASE(
  "Rejected stale transaction must not discard a concurrent current-view "
  "transaction" *
  doctest::test_suite("view_straddling_rollback"))
{
  Fixture fixture;
  fixture.start();

  INFO("Apply and serialise A at seqno 2 in the initial view");
  const auto stale_txid = fixture.store->next_txid();
  REQUIRE(stale_txid == ccf::TxID(fixture.initial_view, 2));
  auto stale_info = [&]() {
    auto tx = fixture.store->create_reserved_tx(stale_txid);
    tx.rw(fixture.table)->put(1, 2);
    return tx.commit_reserved();
  }();
  REQUIRE(stale_info.success == ccf::kv::CommitResult::SUCCESS);
  REQUIRE(read_value(*fixture.store, fixture.table, 1) == 2);

  INFO("A enters Store::commit, passes its view check, then is descheduled");
  CommitPause stale_pause;
  std::optional<ccf::kv::CommitResult> stale_result;
  Worker stale_worker({&stale_pause}, [&]() {
    stale_result = fixture.store->commit(
      stale_txid,
      std::make_unique<PausingMovePendingTx>(
        std::move(stale_info), stale_pause),
      false);
  });
  REQUIRE(stale_pause.wait_until_paused());

  INFO("Lose leadership and win a later election, rolling back to seqno 1");
  const auto reelection_view = fixture.reelect();
  REQUIRE(fixture.store->current_txid() == ccf::TxID(fixture.initial_view, 1));
  REQUIRE_FALSE(read_value(*fixture.store, fixture.table, 1).has_value());
  REQUIRE(fixture.raft->get_last_idx() == 1);

  INFO(
    "B is applied at seqno 2 in the new view, then pauses before "
    "Store::commit");
  auto current_tx = fixture.store->create_tx();
  current_tx.rw(fixture.table)->put(2, 3);
  CommitPause current_pause;
  std::optional<ccf::kv::CommitResult> current_result;
  Worker current_worker({&current_pause}, [&]() {
    current_result = current_tx.commit(
      ccf::empty_claims(),
      [&current_pause](const auto&, const auto&) { current_pause.pause(); });
  });
  REQUIRE(current_pause.wait_until_paused());
  REQUIRE(current_tx.get_txid() == ccf::TxID(reelection_view, 2));
  REQUIRE(fixture.store->current_txid() == ccf::TxID(reelection_view, 2));
  REQUIRE(read_value(*fixture.store, fixture.table, 2) == 3);

  INFO(
    "Resume A: consensus rejects it, and B's local application must "
    "survive");
  stale_pause.release();
  stale_worker.join();
  REQUIRE(stale_result.has_value());
  CHECK(stale_result.value() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  MESSAGE("After A is rejected: " << describe(fixture));
  CHECK(fixture.raft->get_last_idx() == 1);
  CHECK(fixture.raft->ledger->ledger.size() == 1);
  CHECK(fixture.store->current_txid() == ccf::TxID(reelection_view, 2));
  CHECK(read_value(*fixture.store, fixture.table, 2) == 3);

  INFO("Resume B: whatever consensus decides, KV and ledger must agree");
  current_pause.release();
  current_worker.join();
  REQUIRE(current_result.has_value());
  CHECK(current_result.value() == ccf::kv::CommitResult::SUCCESS);
  MESSAGE("After B is replicated: " << describe(fixture));
  CHECK(fixture.raft->get_last_idx() == 2);
  CHECK(fixture.raft->ledger->ledger.size() == 2);
  CHECK(fixture.store->current_txid() == ccf::TxID(reelection_view, 2));
  CHECK(read_value(*fixture.store, fixture.table, 2) == 3);

  INFO("The next transaction gets a fresh seqno and replicates normally");
  auto next_tx = fixture.store->create_tx();
  next_tx.rw(fixture.table)->put(3, 4);
  CHECK(next_tx.commit() == ccf::kv::CommitResult::SUCCESS);
  const auto next_txid = next_tx.get_txid();
  MESSAGE(
    "After next tx " << (next_txid.has_value() ? next_txid->to_str() :
                                                 std::string("none"))
                     << ": " << describe(fixture));
  CHECK(next_txid == ccf::TxID(reelection_view, 3));
  CHECK(fixture.store->current_txid() == ccf::TxID(reelection_view, 3));
  CHECK(read_value(*fixture.store, fixture.table, 3) == 4);
  CHECK(fixture.raft->get_last_idx() == 3);
  CHECK(fixture.raft->ledger->ledger.size() == 3);
}
