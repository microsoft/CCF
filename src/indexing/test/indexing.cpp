// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/indexing/strategies/seqnos_by_key_bucketed.h"
#include "ccf/indexing/strategies/seqnos_by_key_in_memory.h"
#include "consensus/aft/raft.h"
#include "consensus/aft/test/logging_stub.h"
#include "ds/test/stub_writer.h"
#include "host/lfs_file_handler.h"
#include "indexing/enclave_lfs_access.h"
#include "indexing/historical_transaction_fetcher.h"
#include "indexing/test/common.h"
#include "node/share_manager.h"

#include <thread>
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

// Transitively see a header that tries to use ThreadMessaging, so need to
// create static singleton
std::unique_ptr<threading::ThreadMessaging>
  threading::ThreadMessaging::singleton = nullptr;

using IndexA = ccf::indexing::strategies::SeqnosByKey_InMemory<decltype(map_a)>;
using LazyIndexA = ccf::indexing::LazyStrategy<IndexA>;

using IndexB = ccf::indexing::strategies::SeqnosByKey_InMemory<decltype(map_b)>;

constexpr size_t certificate_validity_period_days = 365;
using namespace std::literals;
auto valid_from =
  ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);
auto valid_to = crypto::compute_cert_valid_to_string(
  valid_from, certificate_validity_period_days);

static std::vector<ActionDesc> create_actions(
  ExpectedSeqNos& seqnos_hello,
  ExpectedSeqNos& seqnos_saluton,
  ExpectedSeqNos& seqnos_1,
  ExpectedSeqNos& seqnos_2)
{
  std::vector<ActionDesc> actions;
  actions.push_back({seqnos_hello, [](size_t i, kv::Tx& tx) {
                       tx.wo(map_a)->put("hello", "value doesn't matter");
                       return true;
                     }});
  actions.push_back({seqnos_saluton, [](size_t i, kv::Tx& tx) {
                       if (i % 2 == 0)
                       {
                         tx.wo(map_a)->put("saluton", "value doesn't matter");
                         return true;
                       }
                       return false;
                     }});
  actions.push_back({seqnos_1, [](size_t i, kv::Tx& tx) {
                       if (i % 3 == 0)
                       {
                         tx.wo(map_b)->put(1, 42);
                         return true;
                       }
                       return false;
                     }});
  actions.push_back({seqnos_2, [](size_t i, kv::Tx& tx) {
                       if (i % 4 == 0)
                       {
                         tx.wo(map_b)->put(2, 42);
                         return true;
                       }
                       return false;
                     }});
  return actions;
}

template <typename AA>
void run_tests(
  const std::function<void()>& tick_until_caught_up,
  kv::Store& kv_store,
  ccf::indexing::Indexer& indexer,
  ExpectedSeqNos& seqnos_hello,
  ExpectedSeqNos& seqnos_saluton,
  ExpectedSeqNos& seqnos_1,
  ExpectedSeqNos& seqnos_2,
  const std::shared_ptr<AA> index_a,
  const std::shared_ptr<IndexB> index_b)
{
  REQUIRE(index_a != nullptr);
  REQUIRE(index_b != nullptr);

  if constexpr (std::is_same_v<AA, LazyIndexA>)
  {
    index_a->extend_index_to(kv_store.current_txid());
  }

  tick_until_caught_up();

  {
    REQUIRE(check_seqnos(seqnos_1, index_b->get_all_write_txs(1)));
    REQUIRE(check_seqnos(seqnos_2, index_b->get_all_write_txs(2)));
  }

  {
    INFO("Sub-ranges can be requested");
    const auto current_seqno = kv_store.current_version();
    const auto sub_range_start = current_seqno / 5;
    const auto sub_range_end = current_seqno / 3;
    const auto invalid_seqno_a = current_seqno + 1;
    const auto invalid_seqno_b = current_seqno * 2;

    const auto full_range_hello =
      index_a->get_write_txs_in_range("hello", 0, current_seqno);
    REQUIRE(full_range_hello.has_value());
    REQUIRE(check_seqnos(seqnos_hello, full_range_hello));

    const auto sub_range_saluton = index_a->get_write_txs_in_range(
      "saluton", sub_range_start, sub_range_end);
    REQUIRE(sub_range_saluton.has_value());
    REQUIRE(check_seqnos(seqnos_saluton, sub_range_saluton, false));

    const auto max_seqnos = 3;
    const auto truncated_sub_range_saluton = index_a->get_write_txs_in_range(
      "saluton", sub_range_start, sub_range_end, max_seqnos);
    REQUIRE(truncated_sub_range_saluton.has_value());
    REQUIRE(truncated_sub_range_saluton->size() == max_seqnos);
    REQUIRE(check_seqnos(seqnos_saluton, truncated_sub_range_saluton, false));

    REQUIRE(check_seqnos(
      seqnos_1, index_b->get_write_txs_in_range(1, 0, current_seqno)));

    REQUIRE(check_seqnos(
      seqnos_2,
      index_b->get_write_txs_in_range(2, sub_range_start, sub_range_end),
      false));

    REQUIRE_FALSE(
      index_a->get_write_txs_in_range("hello", 0, invalid_seqno_a).has_value());
    REQUIRE_FALSE(
      index_a
        ->get_write_txs_in_range("unused_key", sub_range_start, invalid_seqno_b)
        .has_value());
    REQUIRE_FALSE(
      index_b->get_write_txs_in_range(1, current_seqno, invalid_seqno_a)
        .has_value());
    REQUIRE_FALSE(
      index_b->get_write_txs_in_range(42, invalid_seqno_a, invalid_seqno_b)
        .has_value());
  }

  {
    INFO("Both indexes continue to be updated with new entries");
    REQUIRE(create_transactions(
      kv_store,
      create_actions(seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2),
      100));

    if constexpr (std::is_same_v<AA, LazyIndexA>)
    {
      index_a->extend_index_to(kv_store.current_txid());
    }

    tick_until_caught_up();

    REQUIRE(check_seqnos(seqnos_hello, index_a->get_all_write_txs("hello")));
    REQUIRE(
      check_seqnos(seqnos_saluton, index_a->get_all_write_txs("saluton")));

    REQUIRE(check_seqnos(seqnos_1, index_b->get_all_write_txs(1)));
    REQUIRE(check_seqnos(seqnos_2, index_b->get_all_write_txs(2)));
  }
}

// Uses stub classes to test just indexing logic in isolation
TEST_CASE("basic indexing" * doctest::test_suite("indexing"))
{
  kv::Store kv_store;

  auto consensus = std::make_shared<AllCommittableConsensus>();
  kv_store.set_consensus(consensus);

  auto fetcher = std::make_shared<TestTransactionFetcher>();
  ccf::indexing::Indexer indexer(fetcher);

  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  REQUIRE_THROWS(indexer.install_strategy(nullptr));

  auto index_a = std::make_shared<IndexA>(map_a);
  REQUIRE(indexer.install_strategy(index_a));
  REQUIRE_FALSE(indexer.install_strategy(index_a));

  static constexpr auto num_transactions =
    ccf::indexing::Indexer::MAX_REQUESTABLE * 3;
  ExpectedSeqNos seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2;
  REQUIRE(create_transactions(
    kv_store,
    create_actions(seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2)));

  auto tick_until_caught_up = [&]() {
    while (indexer.update_strategies(step_time, kv_store.current_txid()) ||
           !fetcher->requested.empty())
    {
      // Do the fetch, simulating an asynchronous fetch by the historical query
      // system
      for (auto seqno : fetcher->requested)
      {
        REQUIRE(consensus->replica.size() >= seqno);
        const auto& entry = std::get<1>(consensus->replica[seqno - 1]);
        fetcher->fetched_stores[seqno] =
          fetcher->deserialise_transaction(seqno, entry->data(), entry->size());
      }
      fetcher->requested.clear();
    }
  };

  tick_until_caught_up();

  {
    INFO("Confirm that pre-existing strategy was populated already");

    REQUIRE(check_seqnos(seqnos_hello, index_a->get_all_write_txs("hello")));
    REQUIRE(
      check_seqnos(seqnos_saluton, index_a->get_all_write_txs("saluton")));
  }

  INFO(
    "Indexes can be installed later, and will be populated after enough "
    "ticks");

  auto index_b = std::make_shared<IndexB>(map_b);
  REQUIRE(indexer.install_strategy(index_b));
  REQUIRE_FALSE(indexer.install_strategy(index_b));

  auto current_ = kv_store.current_txid();
  ccf::TxID current{current_.term, current_.version};
  REQUIRE(index_a->get_indexed_watermark() == current);
  REQUIRE(index_b->get_indexed_watermark() == ccf::TxID());

  tick_until_caught_up();

  REQUIRE(index_a->get_indexed_watermark() == current);
  REQUIRE(index_b->get_indexed_watermark() == current);

  run_tests(
    tick_until_caught_up,
    kv_store,
    indexer,
    seqnos_hello,
    seqnos_saluton,
    seqnos_1,
    seqnos_2,
    index_a,
    index_b);
}

kv::Version rekey(
  kv::Store& kv_store,
  const std::shared_ptr<ccf::LedgerSecrets>& ledger_secrets)
{
  // This isn't really used, but is needed for ShareManager, so can be recreated
  // each time here
  ccf::NetworkState network;
  network.ledger_secrets = ledger_secrets;
  ccf::ShareManager share_manager(network);

  auto tx = kv_store.create_tx();
  auto new_ledger_secret = ccf::make_ledger_secret();
  share_manager.issue_recovery_shares(tx, new_ledger_secret);
  REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);

  auto tx_version = tx.commit_version();

  ledger_secrets->set_secret(
    tx_version + 1,
    std::make_shared<ccf::LedgerSecret>(
      std::move(new_ledger_secret->raw_key), tx_version));

  return tx_version;
}

aft::LedgerStubProxy* add_raft_consensus(
  std::shared_ptr<kv::Store> kv_store,
  std::shared_ptr<ccf::indexing::Indexer> indexer)
{
  using TRaft = aft::Aft<aft::LedgerStubProxy>;
  using AllCommittableRaftConsensus = AllCommittableWrapper<TRaft>;
  using ms = std::chrono::milliseconds;
  const std::string node_id = "Node 0";
  const consensus::Configuration settings{
    ConsensusType::CFT, {"20ms"}, {"100ms"}};
  auto consensus = std::make_shared<AllCommittableRaftConsensus>(
    settings,
    std::make_unique<aft::Adaptor<kv::Store>>(kv_store),
    std::make_unique<aft::LedgerStubProxy>(node_id),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id),
    nullptr,
    nullptr);

  aft::Configuration::Nodes initial_config;
  initial_config[node_id] = {};
  consensus->add_configuration(0, initial_config);

  consensus->force_become_primary();

  kv_store->set_consensus(consensus);

  return consensus->ledger.get();
}

// Uses the real classes, to test their interaction with indexing
TEST_CASE_TEMPLATE(
  "integrated indexing" * doctest::test_suite("indexing"),
  AA,
  IndexA,
  LazyIndexA)
{
  auto kv_store_p = std::make_shared<kv::Store>();
  auto& kv_store = *kv_store_p;

  auto ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  kv_store.set_encryptor(std::make_shared<ccf::NodeEncryptor>(ledger_secrets));

  auto stub_writer = std::make_shared<StubWriter>();
  auto cache = std::make_shared<ccf::historical::StateCacheImpl>(
    kv_store, ledger_secrets, stub_writer);

  auto fetcher =
    std::make_shared<ccf::indexing::HistoricalTransactionFetcher>(cache);
  auto indexer_p = std::make_shared<ccf::indexing::Indexer>(fetcher);
  auto& indexer = *indexer_p;

  auto index_a = std::make_shared<AA>(map_a);
  REQUIRE(indexer.install_strategy(index_a));

  auto ledger = add_raft_consensus(kv_store_p, indexer_p);

  ledger_secrets->init();
  {
    INFO("Store one recovery member");
    // This is necessary to rekey the ledger and issue recovery shares for the
    // new ledger secret
    auto tx = kv_store.create_tx();
    auto config = tx.rw<ccf::Configuration>(ccf::Tables::CONFIGURATION);
    constexpr size_t recovery_threshold = 1;
    config->put({recovery_threshold});
    auto member_info = tx.rw<ccf::MemberInfo>(ccf::Tables::MEMBER_INFO);
    auto member_public_encryption_keys = tx.rw<ccf::MemberPublicEncryptionKeys>(
      ccf::Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS);

    auto kp = crypto::make_key_pair();
    auto cert = kp->self_sign("CN=member", valid_from, valid_to);
    auto member_id =
      crypto::Sha256Hash(crypto::cert_pem_to_der(cert)).hex_str();

    member_info->put(member_id, {ccf::MemberStatus::ACTIVE});
    member_public_encryption_keys->put(
      member_id, crypto::make_rsa_key_pair()->public_key_pem());
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  ExpectedSeqNos seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2;
  auto actions =
    create_actions(seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2);
  for (size_t i = 0; i < 3; ++i)
  {
    REQUIRE(create_transactions(kv_store, actions, 10));
    rekey(kv_store, ledger_secrets);
  }

  REQUIRE(create_transactions(kv_store, actions));

  size_t handled_writes = 0;
  const auto& writes = stub_writer->writes;

  auto tick_until_caught_up = [&]() {
    size_t loops = 0;
    while (indexer.update_strategies(step_time, kv_store.current_txid()) ||
           handled_writes < writes.size())
    {
      cache->tick(ccf::historical::slow_fetch_threshold / 2);

      // Do the fetch, simulating an asynchronous fetch by the historical
      // query system
      for (auto it = writes.begin() + handled_writes; it != writes.end(); ++it)
      {
        const auto& write = *it;

        const uint8_t* data = write.contents.data();
        size_t size = write.contents.size();
        REQUIRE(write.m == consensus::ledger_get_range);
        auto [from_seqno, to_seqno, purpose_] =
          ringbuffer::read_message<consensus::ledger_get_range>(data, size);
        auto& purpose = purpose_;
        REQUIRE(purpose == consensus::LedgerRequestPurpose::HistoricalQuery);

        std::vector<uint8_t> combined;
        for (auto seqno = from_seqno; seqno <= to_seqno; ++seqno)
        {
          const auto entry = ledger->get_raw_entry_by_idx(seqno);
          REQUIRE(entry.has_value());
          combined.insert(combined.end(), entry->begin(), entry->end());
        }
        cache->handle_ledger_entries(from_seqno, to_seqno, combined);
      }

      handled_writes = writes.end() - writes.begin();

      if (loops++ > 100)
      {
        throw std::logic_error("Looks like a permanent loop");
      }
    }
  };

  tick_until_caught_up();

  if constexpr (std::is_same_v<AA, LazyIndexA>)
  {
    INFO("Lazy indexes require an additional prod to be populated");

    REQUIRE(index_a->get_all_write_txs("hello")->empty());
    REQUIRE(index_a->get_all_write_txs("saluton")->empty());

    index_a->extend_index_to(kv_store.current_txid());
    tick_until_caught_up();

    REQUIRE_FALSE(index_a->get_all_write_txs("hello")->empty());
    REQUIRE_FALSE(index_a->get_all_write_txs("saluton")->empty());
  }

  {
    INFO("Confirm that pre-existing strategy was populated already");

    REQUIRE(check_seqnos(seqnos_hello, index_a->get_all_write_txs("hello")));
    REQUIRE(
      check_seqnos(seqnos_saluton, index_a->get_all_write_txs("saluton")));
  }

  INFO(
    "Indexes can be installed later, and will be populated after enough "
    "ticks");

  auto index_b = std::make_shared<IndexB>(map_b);
  REQUIRE(indexer.install_strategy(index_b));

  run_tests(
    tick_until_caught_up,
    kv_store,
    indexer,
    seqnos_hello,
    seqnos_saluton,
    seqnos_1,
    seqnos_2,
    index_a,
    index_b);
}

using namespace std::chrono_literals;
const auto max_multithread_run_time = 10s;

// Uses the real classes, and access + update them concurrently
TEST_CASE(
  "multi-threaded indexing - in memory" * doctest::test_suite("indexing"))
{
  auto kv_store_p = std::make_shared<kv::Store>();
  auto& kv_store = *kv_store_p;

  auto ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  kv_store.set_encryptor(std::make_shared<ccf::NodeEncryptor>(ledger_secrets));

  auto stub_writer = std::make_shared<StubWriter>();
  auto cache = std::make_shared<ccf::historical::StateCacheImpl>(
    kv_store, ledger_secrets, stub_writer);

  auto fetcher =
    std::make_shared<ccf::indexing::HistoricalTransactionFetcher>(cache);
  auto indexer_p = std::make_shared<ccf::indexing::Indexer>(fetcher);
  auto& indexer = *indexer_p;

  auto index_a = std::make_shared<IndexA>(map_a);
  REQUIRE(indexer.install_strategy(index_a));

  auto index_b = std::make_shared<IndexB>(map_b);
  REQUIRE(indexer.install_strategy(index_b));

  auto ledger = add_raft_consensus(kv_store_p, indexer_p);

  ledger_secrets->init();
  {
    INFO("Store one recovery member");
    // This is necessary to rekey the ledger and issue recovery shares for the
    // new ledger secret
    auto tx = kv_store.create_tx();
    auto config = tx.rw<ccf::Configuration>(ccf::Tables::CONFIGURATION);
    constexpr size_t recovery_threshold = 1;
    config->put({recovery_threshold});
    auto member_info = tx.rw<ccf::MemberInfo>(ccf::Tables::MEMBER_INFO);
    auto member_public_encryption_keys = tx.rw<ccf::MemberPublicEncryptionKeys>(
      ccf::Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS);

    auto kp = crypto::make_key_pair();
    auto cert = kp->self_sign("CN=member", valid_from, valid_to);
    auto member_id =
      crypto::Sha256Hash(crypto::cert_pem_to_der(cert)).hex_str();

    member_info->put(member_id, {ccf::MemberStatus::ACTIVE});
    member_public_encryption_keys->put(
      member_id, crypto::make_rsa_key_pair()->public_key_pem());
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  std::atomic<bool> finished = false;
  std::atomic<size_t> writes_to_hello = 0;
  std::atomic<size_t> writes_to_saluton = 0;
  std::atomic<size_t> writes_to_42 = 0;

  auto tx_advancer = [&]() {
    size_t i = 0;
    while (i < 1'000)
    {
      auto tx = kv_store.create_tx();
      tx.wo(map_a)->put(fmt::format("hello"), fmt::format("Value {}", i));
      ++writes_to_hello;
      if (i % 2 == 0)
      {
        ++writes_to_saluton;
        tx.wo(map_a)->put(fmt::format("saluton"), fmt::format("Value2 {}", i));
      }
      if (i % 3 == 0)
      {
        ++writes_to_42;
        tx.wo(map_b)->put(42, i);
      }

      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
      ++i;
    }
    finished = true;
  };

  size_t handled_writes = 0;
  const auto& writes = stub_writer->writes;

  auto fetch_index_a = [&]() {
    while (true)
    {
      const auto hello = index_a->get_all_write_txs("hello");
      const auto saluton = index_a->get_all_write_txs("saluton");

      if (
        finished && hello.has_value() && hello->size() == writes_to_hello &&
        saluton.has_value() && saluton->size() == writes_to_saluton)
      {
        break;
      }
    }
  };

  auto fetch_index_b = [&]() {
    while (true)
    {
      const auto forty_two = index_b->get_all_write_txs(42);

      if (
        finished && forty_two.has_value() && forty_two->size() == writes_to_42)
      {
        break;
      }
    }
  };

  std::atomic<bool> work_done = false;

  std::thread index_ticker([&]() {
    while (!work_done)
    {
      size_t post_work_done_loops = 0;
      while (indexer.update_strategies(step_time, kv_store.current_txid()) ||
             handled_writes < writes.size())
      {
        cache->tick(ccf::historical::slow_fetch_threshold / 2);

        // Do the fetch, simulating an asynchronous fetch by the historical
        // query system
        for (auto it = writes.begin() + handled_writes; it != writes.end();
             ++it)
        {
          const auto& write = *it;

          const uint8_t* data = write.contents.data();
          size_t size = write.contents.size();
          REQUIRE(write.m == consensus::ledger_get_range);
          auto [from_seqno, to_seqno, purpose_] =
            ringbuffer::read_message<consensus::ledger_get_range>(data, size);
          auto& purpose = purpose_;
          REQUIRE(purpose == consensus::LedgerRequestPurpose::HistoricalQuery);

          std::vector<uint8_t> combined;
          for (auto seqno = from_seqno; seqno <= to_seqno; ++seqno)
          {
            auto entry = ledger->get_raw_entry_by_idx(seqno);
            if (!entry.has_value())
            {
              // Possible that this operation beat consensus to the ledger, so
              // pause and retry
              std::this_thread::sleep_for(std::chrono::milliseconds(50));
              entry = ledger->get_raw_entry_by_idx(seqno);
            }
            REQUIRE(entry.has_value());
            combined.insert(combined.end(), entry->begin(), entry->end());
          }
          cache->handle_ledger_entries(from_seqno, to_seqno, combined);
        }

        handled_writes = writes.end() - writes.begin();

        if (work_done)
        {
          if (post_work_done_loops++ > 100)
          {
            throw std::logic_error("Looks like a permanent loop");
          }
        }
      }
    }
  });

  std::vector<std::thread> threads;
  threads.emplace_back(tx_advancer);
  threads.emplace_back(fetch_index_a);
  threads.emplace_back(fetch_index_a);
  threads.emplace_back(fetch_index_a);
  threads.emplace_back(fetch_index_b);
  threads.emplace_back(fetch_index_b);

  std::thread watchdog([&]() {
    using Clock = std::chrono::system_clock;
    const auto start_time = Clock::now();

    while (!work_done)
    {
      const auto now = Clock::now();
      REQUIRE(now - start_time < max_multithread_run_time);
      std::this_thread::sleep_for(50ms);
    }
  });

  for (auto& thread : threads)
  {
    thread.join();
  }

  work_done = true;
  index_ticker.join();
  watchdog.join();
}

class MockTransactionFetcher : public ccf::indexing::TransactionFetcher
{
  std::shared_ptr<kv::AbstractTxEncryptor> encryptor;

public:
  aft::LedgerStubProxy* ledger;

  MockTransactionFetcher(const std::shared_ptr<kv::AbstractTxEncryptor>& e) :
    encryptor(e)
  {}

  kv::ReadOnlyStorePtr deserialise_transaction(
    ccf::SeqNo seqno, const uint8_t* data, size_t size) override
  {
    auto store = std::make_shared<kv::Store>(
      false /* Do not start from very first seqno */,
      true /* Make use of historical secrets */);

    store->set_encryptor(encryptor);

    bool public_only = false;
    auto exec =
      store->deserialize({data, data + size}, ConsensusType::CFT, public_only);
    if (exec == nullptr)
    {
      return nullptr;
    }

    auto result = exec->apply();
    if (result == kv::ApplyResult::FAIL)
    {
      return nullptr;
    }

    return store;
  }

  std::vector<kv::ReadOnlyStorePtr> fetch_transactions(
    const ccf::SeqNoCollection& seqnos) override
  {
    std::vector<kv::ReadOnlyStorePtr> ret;

    for (const auto& seqno : seqnos)
    {
      const auto entry = ledger->get_raw_entry_by_idx(seqno);
      if (!entry.has_value())
      {
        return {};
      }

      ret.push_back(
        deserialise_transaction(seqno, entry->data(), entry->size()));
    }

    return ret;
  }
};

TEST_CASE(
  "multi-threaded indexing - bucketed" * doctest::test_suite("indexing"))
{
  const auto seed = time(NULL);
  INFO("Using seed: ", seed);
  srand(seed);

  auto kv_store_p = std::make_shared<kv::Store>();
  auto& kv_store = *kv_store_p;

  auto ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(ledger_secrets);
  kv_store.set_encryptor(encryptor);

  auto stub_writer = std::make_shared<StubWriter>();
  auto cache = std::make_shared<ccf::historical::StateCacheImpl>(
    kv_store, ledger_secrets, stub_writer);

  auto fetcher = std::make_shared<MockTransactionFetcher>(encryptor);
  auto indexer_p = std::make_shared<ccf::indexing::Indexer>(fetcher);
  auto& indexer = *indexer_p;

  messaging::BufferProcessor host_bp("lfs_host");
  messaging::BufferProcessor enclave_bp("lfs_enclave");

  constexpr size_t buf_size = 1 << 16;
  auto inbound_buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);
  ringbuffer::Reader inbound_reader(inbound_buffer->bd);
  auto outbound_buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);

  ringbuffer::Reader outbound_reader(outbound_buffer->bd);
  asynchost::LFSFileHandler host_files(
    std::make_shared<ringbuffer::Writer>(inbound_reader));
  host_files.register_message_handlers(host_bp.get_dispatcher());

  auto enclave_lfs = std::make_shared<ccf::indexing::EnclaveLFSAccess>(
    std::make_shared<ringbuffer::Writer>(outbound_reader));
  enclave_lfs->register_message_handlers(enclave_bp.get_dispatcher());

  ccfapp::AbstractNodeContext node_context;
  node_context.install_subsystem(enclave_lfs);

  using IndexA_Bucketed =
    ccf::indexing::strategies::SeqnosByKey_Bucketed<decltype(map_a)>;
  auto index_a = std::make_shared<IndexA_Bucketed>(map_a, node_context, 100, 5);
  REQUIRE(indexer.install_strategy(index_a));

  auto index_b = std::make_shared<IndexB>(map_b);
  REQUIRE(indexer.install_strategy(index_b));

  auto ledger = add_raft_consensus(kv_store_p, indexer_p);
  fetcher->ledger = ledger;

  ledger_secrets->init();
  {
    INFO("Store one recovery member");
    // This is necessary to rekey the ledger and issue recovery shares for the
    // new ledger secret
    auto tx = kv_store.create_tx();
    auto config = tx.rw<ccf::Configuration>(ccf::Tables::CONFIGURATION);
    constexpr size_t recovery_threshold = 1;
    config->put({recovery_threshold});
    auto member_info = tx.rw<ccf::MemberInfo>(ccf::Tables::MEMBER_INFO);
    auto member_public_encryption_keys = tx.rw<ccf::MemberPublicEncryptionKeys>(
      ccf::Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS);

    auto kp = crypto::make_key_pair();
    auto cert = kp->self_sign("CN=member", valid_from, valid_to);
    auto member_id =
      crypto::Sha256Hash(crypto::cert_pem_to_der(cert)).hex_str();

    member_info->put(member_id, {ccf::MemberStatus::ACTIVE});
    member_public_encryption_keys->put(
      member_id, crypto::make_rsa_key_pair()->public_key_pem());
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  std::atomic<bool> all_submitted = false;
  std::atomic<size_t> writes_to_hello = 0;
  std::atomic<size_t> writes_to_saluton = 0;
  std::atomic<size_t> writes_to_42 = 0;

  auto tx_advancer = [&]() {
    size_t i = 0;
    constexpr auto tx_count =
#if NDEBUG
      1'000;
#else
      100;
#endif

    while (i < tx_count)
    {
      auto tx = kv_store.create_tx();
      tx.wo(map_a)->put(fmt::format("hello"), fmt::format("Value {}", i));
      ++writes_to_hello;
      if (i % 2 == 0)
      {
        ++writes_to_saluton;
        tx.wo(map_a)->put(fmt::format("saluton"), fmt::format("Value2 {}", i));
      }
      if (i % 3 == 0)
      {
        ++writes_to_42;
        tx.wo(map_b)->put(42, i);
      }

      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
      ++i;
      std::this_thread::yield();
    }
    all_submitted = true;
  };

  auto get_all =
    [&](const std::string& key) -> std::optional<ccf::SeqNoCollection> {
    const auto max_range = index_a->max_requestable_range();
    auto range_start = 0;

    ccf::SeqNoCollection all_results;

    while (true)
    {
      const auto end_seqno = kv_store.get_txid().seqno;
      const auto range_end = std::min(end_seqno, range_start + max_range);

      auto results =
        index_a->get_write_txs_in_range(key, range_start, range_end);

      while (!results.has_value())
      {
        // May be contesting for limited cached buckets with other users of this
        // index (no handle for unique claims). Uniform random sleep to avoid
        // deadlock.
        const auto sleep_time = std::chrono::milliseconds(rand() % 100);
        std::this_thread::sleep_for(sleep_time);

        results = index_a->get_write_txs_in_range(key, range_start, range_end);
      }

      for (auto seqno : *results)
      {
        all_results.insert(seqno);
      }

      if (range_end == end_seqno)
      {
        return all_results;
      }
      else
      {
        range_start = range_end + 1;
      }
    }
  };

  auto fetch_index_a = [&]() {
    while (true)
    {
      const auto hello = get_all("hello");
      const auto saluton = get_all("saluton");

      if (
        all_submitted && hello.has_value() &&
        hello->size() == writes_to_hello && saluton.has_value() &&
        saluton->size() == writes_to_saluton)
      {
        break;
      }

      std::this_thread::yield();
    }
  };

  auto fetch_index_b = [&]() {
    while (true)
    {
      const auto forty_two = index_b->get_all_write_txs(42);

      if (
        all_submitted && forty_two.has_value() &&
        forty_two->size() == writes_to_42)
      {
        break;
      }

      std::this_thread::yield();
    }
  };

  std::vector<std::thread> threads;
  threads.emplace_back(tx_advancer);
  threads.emplace_back(fetch_index_a);
  threads.emplace_back(fetch_index_a);
  threads.emplace_back(fetch_index_a);
  threads.emplace_back(fetch_index_b);
  threads.emplace_back(fetch_index_b);

  std::atomic<bool> work_done = false;

  std::thread ringbuffer_flusher([&]() {
    while (!work_done)
    {
      host_bp.read_all(outbound_reader);
      enclave_bp.read_all(inbound_reader);
      std::this_thread::yield();
    }
  });

  std::thread index_ticker([&]() {
    while (!work_done)
    {
      while (indexer.update_strategies(step_time, kv_store.current_txid()))
      {
        std::this_thread::yield();
      }
    }
  });

  std::thread watchdog([&]() {
    using Clock = std::chrono::system_clock;
    const auto start_time = Clock::now();

    while (!work_done)
    {
      const auto now = Clock::now();
      REQUIRE(now - start_time < max_multithread_run_time);
      std::this_thread::sleep_for(50ms);
    }
  });

  for (auto& thread : threads)
  {
    thread.join();
  }

  work_done = true;
  ringbuffer_flusher.join();
  index_ticker.join();
  watchdog.join();
}