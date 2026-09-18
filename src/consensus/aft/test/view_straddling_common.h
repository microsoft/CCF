// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Harness driving a real ccf::kv::Store through a single-node aft::Aft, so
// that Store::commit(), Raft::replicate() and Raft::rollback() interleave as
// they do in production. Adapted from the harness in PR #8209.

#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "test_common.h"

#include <condition_variable>
#include <doctest/doctest.h>
#include <mutex>
#include <optional>
#include <thread>

namespace straddling
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

  // Behaves like ccf::kv::MovePendingTx, the PendingTx of every normal
  // transaction: hands over an already-serialised entry and cannot fail. It
  // pauses first, modelling the committing thread being descheduled after
  // Store::commit() has checked the transaction's view and released
  // version_lock, but before it reaches consensus. In production this is the
  // thread blocking on aft::State::lock while an election holds it.
  class PausingMovePendingTx : public ccf::kv::PendingTx
  {
    ccf::kv::PendingTxInfo info;
    CommitPause& pause;

  public:
    PausingMovePendingTx(ccf::kv::PendingTxInfo&& info_, CommitPause& pause_) :
      info(std::move(info_)),
      pause(pause_)
    {}

    ccf::kv::PendingTxInfo call() override
    {
      pause.pause();
      return std::move(info);
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
    }

    // Split from the constructor so that a derived fixture can install a
    // history before consensus is created and the baseline is committed.
    void start()
    {
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

    // Lose leadership, then win a later election. become_leader() rolls the
    // Store back to the last committable index (1) under the new view.
    ccf::View reelect()
    {
      raft->become_aware_of_new_term(raft->get_view() + 1);
      raft->force_become_primary();
      return raft->get_view();
    }
  };
}
