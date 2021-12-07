// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/indexing/seqnos_by_key.h"
#include "consensus/aft/raft.h"
#include "consensus/aft/raft_consensus.h"
#include "consensus/aft/test/logging_stub.h"
#include "ds/test/stub_writer.h"
#include "indexing/historical_transaction_fetcher.h"
#include "indexing/indexer.h"
#include "kv/test/stub_consensus.h"
#include "node/share_manager.h"

// Needed by TestTransactionFetcher
#include "kv/test/null_encryptor.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

// Transitively see a header that tries to use ThreadMessaging, so need to
// initialise here
threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> threading::ThreadMessaging::thread_count = 1;

using MapA = kv::Map<std::string, std::string>;
using MapB = kv::Map<size_t, size_t>;
kv::Map<std::string, std::string> map_a("private_map_a");
using IndexA = ccf::indexing::strategies::SeqnosByKey<decltype(map_a)>;

kv::Map<size_t, size_t> map_b("private_map_b");
using IndexB = ccf::indexing::strategies::SeqnosByKey<decltype(map_b)>;

class TestTransactionFetcher : public ccf::indexing::TransactionFetcher
{
public:
  std::shared_ptr<kv::NullTxEncryptor> encryptor =
    std::make_shared<kv::NullTxEncryptor>();

  ccf::indexing::SeqNoCollection requested;
  std::unordered_map<ccf::SeqNo, ccf::indexing::StorePtr> fetched_stores;

  ccf::indexing::StorePtr deserialise_transaction(
    ccf::SeqNo seqno, const uint8_t* data, size_t size)
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

  std::vector<ccf::indexing::StorePtr> fetch_transactions(
    const ccf::indexing::SeqNoCollection& seqnos)
  {
    std::vector<ccf::indexing::StorePtr> stores;

    for (auto seqno : seqnos)
    {
      auto it = fetched_stores.find(seqno);
      if (it != fetched_stores.end())
      {
        stores.push_back(it->second);

        // For simplicity, we instantly erase fetched stores here
        it = fetched_stores.erase(it);
      }
      else
      {
        requested.insert(seqno);
      }
    }

    return stores;
  }
};

class IndexingConsensus : public kv::test::StubConsensus
{
public:
  ccf::indexing::Indexer& indexer;

  IndexingConsensus(ccf::indexing::Indexer& i) : indexer(i) {}

  bool replicate(const kv::BatchVector& entries, ccf::View view) override
  {
    auto replicated = kv::test::StubConsensus::replicate(entries, view);

    for (const auto& [seqno, data, committable, hooks] : entries)
    {
      indexer.append_entry({view, seqno}, data->data(), data->size());
    }
    indexer.commit(committed_txid);

    return replicated;
  }
};

template <typename TConsensus>
class AllCommittableConsensus : public TConsensus
{
public:
  using TConsensus::TConsensus;

  bool replicate(const kv::BatchVector& entries_, ccf::View view) override
  {
    // Rather than building a history that produces real signatures, we just
    // overwrite the entries here to say that everything is committable
    kv::BatchVector entries(entries_);
    for (auto& [seqno, data, committable, hooks] : entries)
    {
      committable = true;
    }

    return TConsensus::replicate(entries, view);
  }
};

using AllCommittableIndexingConsensus =
  AllCommittableConsensus<IndexingConsensus>;

using ExpectedSeqNos = std::set<ccf::SeqNo>;

void check_seqnos(
  const ExpectedSeqNos& expected,
  const ccf::indexing::SeqNoCollection& actual,
  bool complete_match = true)
{
  if (complete_match)
  {
    REQUIRE(expected.size() == actual.size());
  }
  else
  {
    REQUIRE(expected.size() >= actual.size());
  }

  for (auto n : actual)
  {
    REQUIRE(expected.contains(n));
  }
}

void create_transactions(
  kv::Store& kv_store,
  ExpectedSeqNos& seqnos_hello,
  ExpectedSeqNos& seqnos_saluton,
  ExpectedSeqNos& seqnos_1,
  ExpectedSeqNos& seqnos_2,
  size_t count = ccf::indexing::Indexer::MAX_REQUESTABLE * 3)
{
  INFO("Create and commit transactions");
  for (size_t i = 0; i < count; ++i)
  {
    const auto write_saluton = i % 3 == 0;
    const auto write_1 = i % 5 == 0;
    const auto write_2 = rand() % 4 != 0;

    auto tx = kv_store.create_tx();
    tx.wo(map_a)->put("hello", "value doesn't matter");
    if (write_saluton)
    {
      tx.wo(map_a)->put("saluton", "value doesn't matter");
    }
    if (write_1)
    {
      tx.wo(map_b)->put(1, 42);
    }
    if (write_2)
    {
      tx.wo(map_b)->put(2, 42);
    }
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);

    const auto seqno = tx.get_txid()->version;
    seqnos_hello.insert(seqno);
    if (write_saluton)
    {
      seqnos_saluton.insert(seqno);
    }
    if (write_1)
    {
      seqnos_1.insert(seqno);
    }
    if (write_2)
    {
      seqnos_2.insert(seqno);
    }
  }
}

void run_tests(
  kv::Store& kv_store,
  ccf::indexing::Indexer& indexer,
  ExpectedSeqNos& seqnos_hello,
  ExpectedSeqNos& seqnos_saluton,
  ExpectedSeqNos& seqnos_1,
  ExpectedSeqNos& seqnos_2,
  const std::shared_ptr<IndexA> index_a,
  const std::shared_ptr<IndexB> index_b)
{
  REQUIRE(index_a != nullptr);
  REQUIRE(index_b != nullptr);

  {
    check_seqnos(seqnos_1, index_b->get_all_write_txs(1));
    check_seqnos(seqnos_2, index_b->get_all_write_txs(2));
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
    check_seqnos(seqnos_hello, *full_range_hello);

    const auto sub_range_saluton = index_a->get_write_txs_in_range(
      "saluton", sub_range_start, sub_range_end);
    REQUIRE(sub_range_saluton.has_value());
    check_seqnos(seqnos_saluton, *sub_range_saluton, false);

    const auto max_seqnos = 3;
    const auto truncated_sub_range_saluton = index_a->get_write_txs_in_range(
      "saluton", sub_range_start, sub_range_end, max_seqnos);
    REQUIRE(truncated_sub_range_saluton.has_value());
    REQUIRE(truncated_sub_range_saluton->size() == max_seqnos);
    check_seqnos(seqnos_saluton, *truncated_sub_range_saluton, false);

    const auto full_range_1 =
      index_b->get_write_txs_in_range(1, 0, current_seqno);
    REQUIRE(full_range_1.has_value());
    check_seqnos(seqnos_1, *full_range_1);

    const auto sub_range_2 =
      index_b->get_write_txs_in_range(2, sub_range_start, sub_range_end);
    REQUIRE(sub_range_2.has_value());
    check_seqnos(seqnos_2, *sub_range_2, false);

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
    create_transactions(
      kv_store, seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2, 100);

    check_seqnos(seqnos_hello, index_a->get_all_write_txs("hello"));
    check_seqnos(seqnos_saluton, index_a->get_all_write_txs("saluton"));

    check_seqnos(seqnos_1, index_b->get_all_write_txs(1));
    check_seqnos(seqnos_2, index_b->get_all_write_txs(2));
  }
}

// Uses stub classes to test just indexing logic in isolation
TEST_CASE("basic indexing")
{
  kv::Store kv_store;
  auto fetcher = std::make_shared<TestTransactionFetcher>();
  ccf::indexing::Indexer indexer(fetcher);

  auto consensus = std::make_shared<AllCommittableIndexingConsensus>(indexer);
  kv_store.set_consensus(consensus);

  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  REQUIRE_THROWS(indexer.install_strategy(nullptr));

  auto index_a = std::make_shared<IndexA>(map_a);
  REQUIRE(indexer.install_strategy(index_a));
  REQUIRE_FALSE(indexer.install_strategy(index_a));

  static constexpr auto num_transactions =
    ccf::indexing::Indexer::MAX_REQUESTABLE * 3;
  ExpectedSeqNos seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2;
  create_transactions(
    kv_store, seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2);

  {
    INFO("Confirm that pre-existing strategy was populated already");

    check_seqnos(seqnos_hello, index_a->get_all_write_txs("hello"));
    check_seqnos(seqnos_saluton, index_a->get_all_write_txs("saluton"));
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

  while (indexer.tick() || !fetcher->requested.empty())
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

  REQUIRE(index_a->get_indexed_watermark() == current);
  REQUIRE(index_b->get_indexed_watermark() == current);

  run_tests(
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
  using TConsensus = aft::Consensus<
    aft::LedgerStubProxy,
    aft::ChannelStubProxy,
    aft::StubSnapshotter>;
  using TRaft =
    aft::Aft<aft::LedgerStubProxy, aft::ChannelStubProxy, aft::StubSnapshotter>;
  using AllCommittableRaftConsensus = AllCommittableConsensus<TConsensus>;
  using ms = std::chrono::milliseconds;
  const std::string node_id = "Node 0";
  auto raft = new TRaft(
    ConsensusType::CFT,
    std::make_unique<aft::Adaptor<kv::Store>>(kv_store),
    std::make_unique<aft::LedgerStubProxy>(node_id),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::StubSnapshotter>(),
    nullptr,
    nullptr,
    std::make_shared<aft::State>(node_id),
    nullptr,
    nullptr,
    indexer,
    ms(20),
    ms(20),
    ms(1000));
  auto consensus = std::make_shared<AllCommittableRaftConsensus>(
    std::unique_ptr<TRaft>(raft), ConsensusType::CFT);

  aft::Configuration::Nodes initial_config;
  initial_config[node_id] = {};
  raft->add_configuration(0, initial_config);

  consensus->force_become_primary();

  kv_store->set_consensus(consensus);

  return raft->ledger.get();
}

// Uses the real classes, to test their interaction with indexing
TEST_CASE("integrated indexing")
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
    auto cert = kp->self_sign("CN=member");
    auto member_id =
      crypto::Sha256Hash(crypto::cert_pem_to_der(cert)).hex_str();

    member_info->put(member_id, {ccf::MemberStatus::ACTIVE});
    member_public_encryption_keys->put(
      member_id, crypto::make_rsa_key_pair()->public_key_pem());
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  ExpectedSeqNos seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2;

  for (size_t i = 0; i < 3; ++i)
  {
    create_transactions(
      kv_store, seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2, 10);
    rekey(kv_store, ledger_secrets);
  }

  create_transactions(
    kv_store, seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2);

  {
    INFO("Confirm that pre-existing strategy was populated already");

    check_seqnos(seqnos_hello, index_a->get_all_write_txs("hello"));
    check_seqnos(seqnos_saluton, index_a->get_all_write_txs("saluton"));
  }

  INFO(
    "Indexes can be installed later, and will be populated after enough "
    "ticks");

  auto index_b = std::make_shared<IndexB>(map_b);
  REQUIRE(indexer.install_strategy(index_b));

  size_t handled_writes = 0;
  const auto& writes = stub_writer->writes;
  size_t loops = 0;
  while (indexer.tick() || handled_writes < writes.size())
  {
    // Do the fetch, simulating an asynchronous fetch by the historical query
    // system
    for (auto it = writes.begin() + handled_writes; it != writes.end(); ++it)
    {
      const auto& write = *it;

      const uint8_t* data = write.contents.data();
      size_t size = write.contents.size();
      REQUIRE(write.m == consensus::ledger_get_range);
      auto [from_seqno, to_seqno, purpose] =
        ringbuffer::read_message<consensus::ledger_get_range>(data, size);
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

  run_tests(
    kv_store,
    indexer,
    seqnos_hello,
    seqnos_saluton,
    seqnos_1,
    seqnos_2,
    index_a,
    index_b);
}
