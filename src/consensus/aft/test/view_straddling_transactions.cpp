// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "test_common.h"

#include <condition_variable>
#include <doctest/doctest.h>
#include <mutex>
#include <thread>

namespace
{
  using TestMap = ccf::kv::Map<size_t, size_t>;
  using Raft = aft::Aft<aft::LedgerStubProxy>;

  class BaselinePendingTx : public ccf::kv::PendingTx
  {
    ccf::TxID txid;
    ccf::kv::Store& store;
    TestMap& table;

  public:
    BaselinePendingTx(
      ccf::TxID txid_, ccf::kv::Store& store_, TestMap& table_) :
      txid(txid_),
      store(store_),
      table(table_)
    {}

    ccf::kv::PendingTxInfo call() override
    {
      auto tx = store.create_reserved_tx(txid);
      tx.rw(table)->put(0, 1);
      return tx.commit_reserved();
    }
  };

  struct CommitPause
  {
    std::mutex lock;
    std::condition_variable paused_cv;
    std::condition_variable resume_cv;
    bool paused = false;
    bool resume = false;

    void pause()
    {
      {
        std::lock_guard<std::mutex> guard(lock);
        paused = true;
      }
      paused_cv.notify_one();

      std::unique_lock<std::mutex> guard(lock);
      resume_cv.wait(guard, [this]() { return resume; });
    }

    void wait_until_paused()
    {
      std::unique_lock<std::mutex> guard(lock);
      paused_cv.wait(guard, [this]() { return paused; });
    }

    void release()
    {
      {
        std::lock_guard<std::mutex> guard(lock);
        resume = true;
      }
      resume_cv.notify_one();
    }
  };

  static std::optional<size_t> read_value(
    ccf::kv::Store& store, TestMap& table, size_t key)
  {
    auto tx = store.create_read_only_tx();
    return tx.ro(table)->get(key);
  }

  struct Fixture
  {
    const ccf::NodeId node_id = ccf::kv::test::PrimaryNodeId;
    std::shared_ptr<ccf::kv::Store> store = std::make_shared<ccf::kv::Store>();
    TestMap table{"public:table"};
    std::shared_ptr<Raft> raft;
    ccf::View initial_view = 0;

    Fixture()
    {
      store->set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
      raft = std::make_shared<Raft>(
        raft_settings,
        std::make_unique<aft::Adaptor<ccf::kv::Store>>(store),
        std::make_unique<aft::LedgerStubProxy>(node_id),
        std::make_shared<aft::ChannelStubProxy>(),
        std::make_shared<aft::State>(node_id),
        nullptr);
      store->set_consensus(raft);

      ccf::kv::Configuration::Nodes configuration;
      configuration.try_emplace(node_id);
      raft->add_configuration(0, configuration);
      raft->force_become_primary();
      initial_view = raft->get_view();

      const auto baseline_txid = store->next_txid();
      REQUIRE(
        store->commit(
          baseline_txid,
          std::make_unique<BaselinePendingTx>(baseline_txid, *store, table),
          true) == ccf::kv::CommitResult::SUCCESS);
      REQUIRE(store->current_txid() == ccf::TxID(initial_view, 1));
      REQUIRE(raft->get_committed_seqno() == 1);
      REQUIRE(raft->ledger->ledger.size() == 1);
    }

    void step_down()
    {
      const auto next_view = raft->get_view() + 1;
      raft->become_aware_of_new_term(next_view);
    }

    ccf::View reelect()
    {
      step_down();
      raft->force_become_primary();
      return raft->get_view();
    }
  };

  static ccf::kv::BatchVector::value_type make_entry(
    const ccf::TxID& tx_id, bool globally_committable = false)
  {
    return {
      tx_id,
      std::make_shared<std::vector<uint8_t>>(16, tx_id.seqno),
      globally_committable,
      std::make_shared<ccf::kv::ConsensusHookPtrs>()};
  }
}

TEST_CASE(
  "Long-lived transaction is rolled back after leadership loss" *
  doctest::test_suite("view_straddling_transactions"))
{
  Fixture fixture;

  INFO("Start applying a local transaction in the initial view");
  auto stale_tx = fixture.store->create_tx();
  stale_tx.rw(fixture.table)->put(1, 2);

  CommitPause pause;
  std::optional<ccf::kv::CommitResult> stale_result;
  std::thread stale_worker([&]() {
    stale_result =
      stale_tx.commit(ccf::empty_claims(), [&pause](const auto&, const auto&) {
        pause.pause();
      });
  });
  pause.wait_until_paused();
  REQUIRE(stale_tx.get_txid() == ccf::TxID(fixture.initial_view, 2));

  INFO("Step down after the transaction has been assigned its old-view TxID");
  fixture.step_down();

  INFO("AFT rejects the transaction and rolls Store back to the baseline");
  pause.release();
  stale_worker.join();
  REQUIRE(stale_result.has_value());
  REQUIRE(stale_result.value() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  REQUIRE(fixture.store->current_txid() == ccf::TxID(fixture.initial_view, 1));
  REQUIRE_FALSE(read_value(*fixture.store, fixture.table, 1).has_value());
  REQUIRE(fixture.raft->get_last_idx() == 1);
  REQUIRE(fixture.raft->ledger->ledger.size() == 1);

  INFO("Win a later election and replicate the next transaction normally");
  fixture.raft->force_become_primary();
  const auto fresh_view = fixture.raft->get_view();
  auto fresh_tx = fixture.store->create_tx();
  fresh_tx.rw(fixture.table)->put(2, 3);
  REQUIRE(fresh_tx.commit() == ccf::kv::CommitResult::SUCCESS);
  REQUIRE(fixture.store->current_txid() == ccf::TxID(fresh_view, 2));
  REQUIRE(read_value(*fixture.store, fixture.table, 2) == 3);
  REQUIRE(fixture.raft->get_last_idx() == 2);
  REQUIRE(fixture.raft->ledger->ledger.size() == 2);
}

TEST_CASE(
  "Read-only transaction can finish after re-election" *
  doctest::test_suite("view_straddling_transactions"))
{
  Fixture fixture;

  INFO("Read the baseline in the initial view");
  auto read_tx = fixture.store->create_tx();
  REQUIRE(read_tx.ro(fixture.table)->get(0) == 1);
  const auto read_txid = fixture.store->current_txid();

  INFO("Lose leadership and win a later election before finishing the read");
  fixture.reelect();

  INFO("The read remains valid at the TxID where it observed state");
  REQUIRE(read_tx.commit() == ccf::kv::CommitResult::SUCCESS);
  REQUIRE(read_tx.get_txid() == read_txid);
  CHECK(fixture.store->current_txid() == read_txid);
  CHECK(fixture.raft->get_last_idx() == 1);
  CHECK(fixture.raft->ledger->ledger.size() == 1);
}

TEST_CASE(
  "Transaction begun before re-election can commit in the new view" *
  doctest::test_suite("view_straddling_transactions"))
{
  Fixture fixture;

  INFO("Read state and prepare writes in the initial view");
  auto tx = fixture.store->create_tx();
  auto handle = tx.rw(fixture.table);
  REQUIRE(handle->get(0) == 1);
  handle->put(1, 2);

  INFO("Win a later election before assigning the transaction a TxID");
  const auto reelection_view = fixture.reelect();

  INFO("Revalidate the read and assign the write a TxID in the new view");
  REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  REQUIRE(tx.get_txid() == ccf::TxID(reelection_view, 2));
  CHECK(fixture.store->current_txid() == ccf::TxID(reelection_view, 2));
  CHECK(read_value(*fixture.store, fixture.table, 1) == 2);
  CHECK(fixture.raft->get_last_idx() == 2);
  CHECK(fixture.raft->ledger->ledger.size() == 2);
}

TEST_CASE(
  "Transaction conflicts when re-election rolls back its read snapshot" *
  doctest::test_suite("view_straddling_transactions"))
{
  Fixture fixture;

  INFO("Read state and prepare writes in the initial view");
  auto tx = fixture.store->create_tx();
  auto handle = tx.rw(fixture.table);
  REQUIRE(handle->get(0) == 1);
  handle->put(1, 2);

  INFO("Create an unreplicated local suffix after the transaction's read");
  REQUIRE(fixture.store->next_txid() == ccf::TxID(fixture.initial_view, 2));
  auto suffix_tx = fixture.store->create_tx();
  suffix_tx.rw(fixture.table)->put(0, 9);
  REQUIRE(suffix_tx.commit() == ccf::kv::CommitResult::SUCCESS);
  REQUIRE(suffix_tx.get_txid() == ccf::TxID(fixture.initial_view, 3));
  REQUIRE(fixture.raft->get_last_idx() == 1);

  INFO("Win a later election, rolling the local suffix back");
  fixture.reelect();
  REQUIRE(read_value(*fixture.store, fixture.table, 0) == 1);

  INFO("The transaction's pre-rollback change set is no longer valid");
  CHECK(tx.commit() == ccf::kv::CommitResult::FAIL_CONFLICT);
  CHECK(fixture.store->current_txid() == ccf::TxID(fixture.initial_view, 1));
  CHECK_FALSE(read_value(*fixture.store, fixture.table, 1).has_value());
  CHECK(fixture.raft->get_last_idx() == 1);
  CHECK(fixture.raft->ledger->ledger.size() == 1);
}

TEST_CASE(
  "Assigned old-view transaction is rolled back after re-election" *
  doctest::test_suite("view_straddling_transactions"))
{
  Fixture fixture;

  INFO("Apply a transaction and assign its TxID in the initial view");
  auto stale_tx = fixture.store->create_tx();
  stale_tx.rw(fixture.table)->put(1, 2);
  CommitPause pause;
  std::optional<ccf::kv::CommitResult> stale_result;
  std::thread stale_worker([&]() {
    stale_result =
      stale_tx.commit(ccf::empty_claims(), [&pause](const auto&, const auto&) {
        pause.pause();
      });
  });
  pause.wait_until_paused();
  REQUIRE(stale_tx.get_txid() == ccf::TxID(fixture.initial_view, 2));

  INFO("Lose leadership and win a later election before replication");
  const auto reelection_view = fixture.reelect();

  INFO("AFT rejects the assigned old-view transaction");
  pause.release();
  stale_worker.join();
  REQUIRE(stale_result.has_value());
  REQUIRE(stale_result.value() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  CHECK(fixture.store->current_txid() == ccf::TxID(fixture.initial_view, 1));
  CHECK_FALSE(read_value(*fixture.store, fixture.table, 1).has_value());
  CHECK(fixture.raft->get_last_idx() == 1);
  CHECK(fixture.raft->ledger->ledger.size() == 1);

  INFO("Replicate a fresh transaction at the next index in the new view");
  auto fresh_tx = fixture.store->create_tx();
  fresh_tx.rw(fixture.table)->put(2, 3);
  CHECK(fresh_tx.commit() == ccf::kv::CommitResult::SUCCESS);
  CHECK(fixture.store->current_txid() == ccf::TxID(reelection_view, 2));
  CHECK(read_value(*fixture.store, fixture.table, 2) == 3);
  CHECK(fixture.raft->get_last_idx() == 2);
  CHECK(fixture.raft->ledger->ledger.size() == 2);
}

TEST_CASE(
  "Rolled-back stale transaction cannot invalidate current-view work" *
  doctest::test_suite("view_straddling_transactions"))
{
  Fixture fixture;

  INFO(
    "Assign an old-view transaction seqno 2, then pause before Store::commit");
  auto stale_tx = fixture.store->create_tx();
  stale_tx.rw(fixture.table)->put(1, 2);
  CommitPause stale_pause;
  std::optional<ccf::kv::CommitResult> stale_result;
  std::thread stale_worker([&]() {
    stale_result = stale_tx.commit(
      ccf::empty_claims(),
      [&stale_pause](const auto&, const auto&) { stale_pause.pause(); });
  });
  stale_pause.wait_until_paused();
  REQUIRE(stale_tx.get_txid() == ccf::TxID(fixture.initial_view, 2));

  INFO("Win a later election, reclaiming seqno 2");
  const auto reelection_view = fixture.reelect();

  INFO("Assign current-view seqno 2, then pause before Store::commit");
  auto current_head = fixture.store->create_tx();
  current_head.rw(fixture.table)->put(2, 3);
  CommitPause current_pause;
  std::optional<ccf::kv::CommitResult> current_result;
  std::thread current_worker([&]() {
    current_result = current_head.commit(
      ccf::empty_claims(),
      [&current_pause](const auto&, const auto&) { current_pause.pause(); });
  });
  current_pause.wait_until_paused();
  REQUIRE(current_head.get_txid() == ccf::TxID(reelection_view, 2));

  INFO("Queue current-view seqno 3 behind the missing seqno 2");
  auto current_suffix = fixture.store->create_tx();
  current_suffix.rw(fixture.table)->put(3, 4);
  REQUIRE(current_suffix.commit() == ccf::kv::CommitResult::SUCCESS);
  REQUIRE(current_suffix.get_txid() == ccf::TxID(reelection_view, 3));

  INFO("Resume old 2.2; Store must reject its invalidated local application");
  stale_pause.release();
  stale_worker.join();
  REQUIRE(stale_result.has_value());
  CHECK(stale_result.value() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);

  INFO("Resume current 3.2, which can now replicate with pending 3.3");
  current_pause.release();
  current_worker.join();
  REQUIRE(current_result.has_value());
  CHECK(current_result.value() == ccf::kv::CommitResult::SUCCESS);

  const auto a = fixture.store->current_txid();
  const auto b = ccf::TxID(reelection_view, 3);
  std::cout << "Current TxID: " << a.to_str() << ", expected: " << b.to_str()
            << std::endl;
  CHECK(fixture.store->current_txid() == ccf::TxID(reelection_view, 3));
  CHECK_FALSE(read_value(*fixture.store, fixture.table, 1).has_value());
  CHECK(read_value(*fixture.store, fixture.table, 2) == 3);
  CHECK(read_value(*fixture.store, fixture.table, 3) == 4);
  CHECK(fixture.raft->get_last_idx() == 3);
  CHECK(fixture.raft->ledger->ledger.size() == 3);

  INFO("Replicate a fresh new-view transaction at seqno 4");
  auto fresh_tx = fixture.store->create_tx();
  fresh_tx.rw(fixture.table)->put(4, 5);
  CHECK(fresh_tx.commit() == ccf::kv::CommitResult::SUCCESS);
  CHECK(fixture.store->current_txid() == ccf::TxID(reelection_view, 4));
  CHECK(read_value(*fixture.store, fixture.table, 4) == 5);
  CHECK(fixture.raft->get_last_idx() == 4);
  CHECK(fixture.raft->ledger->ledger.size() == 4);
}

TEST_CASE(
  "Rolled-back stale suffix cannot block a current-view prefix" *
  doctest::test_suite("view_straddling_transactions"))
{
  Fixture fixture;

  INFO("Reserve old-view seqno 2, leaving a hole before stale seqno 3");
  REQUIRE(fixture.store->next_txid() == ccf::TxID(fixture.initial_view, 2));

  auto stale_suffix = fixture.store->create_tx();
  stale_suffix.rw(fixture.table)->put(1, 2);
  CommitPause stale_pause;
  std::optional<ccf::kv::CommitResult> stale_result;
  std::thread stale_worker([&]() {
    stale_result = stale_suffix.commit(
      ccf::empty_claims(),
      [&stale_pause](const auto&, const auto&) { stale_pause.pause(); });
  });
  stale_pause.wait_until_paused();
  REQUIRE(stale_suffix.get_txid() == ccf::TxID(fixture.initial_view, 3));

  INFO("Win a later election, rolling back the old reservation and write");
  const auto reelection_view = fixture.reelect();

  INFO(
    "Apply the current-view transaction at seqno 2, then pause before "
    "Store::commit");
  auto current_tx = fixture.store->create_tx();
  current_tx.rw(fixture.table)->put(2, 3);
  CommitPause current_pause;
  std::optional<ccf::kv::CommitResult> current_result;
  std::thread current_worker([&]() {
    current_result = current_tx.commit(
      ccf::empty_claims(),
      [&current_pause](const auto&, const auto&) { current_pause.pause(); });
  });
  current_pause.wait_until_paused();
  REQUIRE(current_tx.get_txid() == ccf::TxID(reelection_view, 2));

  INFO("Resume stale 2.3; Store must reject its invalidated local application");
  stale_pause.release();
  stale_worker.join();
  REQUIRE(stale_result.has_value());
  CHECK(stale_result.value() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);

  INFO("Resume seqno 2; AFT can accept the current-view transaction");
  current_pause.release();
  current_worker.join();

  REQUIRE(current_result.has_value());
  CHECK(current_result.value() == ccf::kv::CommitResult::SUCCESS);
  CHECK(fixture.store->current_txid() == ccf::TxID(reelection_view, 2));
  CHECK_FALSE(read_value(*fixture.store, fixture.table, 1).has_value());
  CHECK(read_value(*fixture.store, fixture.table, 2) == 3);
  CHECK(fixture.raft->get_last_idx() == 2);
  CHECK(fixture.raft->ledger->ledger.size() == 2);

  INFO("Replicate the next new-view transaction at seqno 3");
  auto fresh_tx = fixture.store->create_tx();
  fresh_tx.rw(fixture.table)->put(3, 4);
  CHECK(fresh_tx.commit() == ccf::kv::CommitResult::SUCCESS);
  CHECK(fixture.store->current_txid() == ccf::TxID(reelection_view, 3));
  CHECK(read_value(*fixture.store, fixture.table, 3) == 4);
  CHECK(fixture.raft->get_last_idx() == 3);
  CHECK(fixture.raft->ledger->ledger.size() == 3);
}

TEST_CASE(
  "AFT accepts a current-view prefix before a stale suffix" *
  doctest::test_suite("view_straddling_transactions"))
{
  const ccf::NodeId node_id = ccf::kv::test::PrimaryNodeId;
  auto store = std::make_shared<aft::LoggingStubStore>(node_id);
  Raft raft(
    raft_settings,
    std::make_unique<aft::Adaptor<aft::LoggingStubStore>>(store),
    std::make_unique<aft::LedgerStubProxy>(node_id),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id),
    nullptr);

  ccf::kv::Configuration::Nodes configuration;
  configuration.try_emplace(node_id);
  raft.add_configuration(0, configuration);
  raft.force_become_primary();

  const auto initial_view = raft.get_view();
  REQUIRE(raft.replicate({make_entry({initial_view, 1}, true)}));
  REQUIRE(raft.get_committed_seqno() == 1);

  raft.become_aware_of_new_term(initial_view + 1);
  raft.force_become_primary();
  const auto current_view = raft.get_view();

  INFO("Submit current 3.2 followed by stale 2.3 in one candidate batch");
  CHECK(raft.replicate(
    {make_entry({current_view, 2}), make_entry({initial_view, 3})}));
  CHECK(raft.get_last_idx() == 2);
  CHECK(raft.ledger->ledger.size() == 2);

  INFO("The next current-view entry can reuse seqno 3");
  CHECK(raft.replicate({make_entry({current_view, 3})}));
  CHECK(raft.get_last_idx() == 3);
  CHECK(raft.ledger->ledger.size() == 3);
}