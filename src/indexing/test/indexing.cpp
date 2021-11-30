// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/test/stub_writer.h"
#include "indexing/historical_transaction_fetcher.h"
#include "indexing/indexer.h"
#include "indexing/seqnos_by_key.h"
#include "kv/test/stub_consensus.h"
#include "node/share_manager.h"

// Needed by TestTransactionFetcher
#include "kv/test/null_encryptor.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

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

  bool replicate(const kv::BatchVector& entries_, ccf::View view) override
  {
    // Rather than building a history that produces real signatures, we just
    // overwrite the entries here to say that everything is committable
    kv::BatchVector entries(entries_);
    for (auto& [seqno, data, committable, hooks] : entries)
    {
      committable = true;
    }

    auto replicated = kv::test::StubConsensus::replicate(entries, view);

    for (const auto& [seqno, data, committable, hooks] : entries)
    {
      indexer.append_entry({view, seqno}, data->data(), data->size());
    }
    indexer.commit(committed_txid);

    return replicated;
  }
};

using SeqNoVec = std::vector<ccf::SeqNo>;

void check_seqnos(
  const SeqNoVec& expected, const ccf::indexing::SeqNoCollection& actual)
{
  REQUIRE(expected.size() == actual.size());

  for (auto n : expected)
  {
    REQUIRE(actual.contains(n));
  }
}

void create_transactions(
  kv::Store& kv_store,
  SeqNoVec& seqnos_hello,
  SeqNoVec& seqnos_saluton,
  SeqNoVec& seqnos_1,
  SeqNoVec& seqnos_2,
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
    seqnos_hello.push_back(seqno);
    if (write_saluton)
    {
      seqnos_saluton.push_back(seqno);
    }
    if (write_1)
    {
      seqnos_1.push_back(seqno);
    }
    if (write_2)
    {
      seqnos_2.push_back(seqno);
    }
  }
}

// Uses stub classes to test just indexing logic in isolation
TEST_CASE("basic indexing")
{
  kv::Store kv_store;
  TestTransactionFetcher fetcher;
  ccf::indexing::Indexer indexer(fetcher);

  auto consensus = std::make_shared<IndexingConsensus>(indexer);
  kv_store.set_consensus(consensus);

  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  REQUIRE_THROWS(indexer.install_strategy(nullptr));

  const auto name_a = indexer.install_strategy(std::make_unique<IndexA>(map_a));
  REQUIRE_THROWS(indexer.install_strategy(std::make_unique<IndexA>(map_a)));

  {
    REQUIRE(indexer.get_strategy<IndexA>(name_a) != nullptr);

    REQUIRE(indexer.get_strategy<IndexA>("some other junk name") == nullptr);
    REQUIRE(indexer.get_strategy<IndexB>(name_a) == nullptr);
  }

  static constexpr auto num_transactions =
    ccf::indexing::Indexer::MAX_REQUESTABLE * 3;
  SeqNoVec seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2;
  create_transactions(
    kv_store, seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2);

  {
    INFO("Confirm that pre-existing strategy was populated already");

    auto index_a = indexer.get_strategy<IndexA>(name_a);
    REQUIRE(index_a != nullptr);

    check_seqnos(seqnos_hello, index_a->get_write_txs("hello"));
    check_seqnos(seqnos_saluton, index_a->get_write_txs("saluton"));
  }

  INFO(
    "Indexes can be installed later, and will be populated after enough "
    "ticks");

  const auto name_b = indexer.install_strategy(std::make_unique<IndexB>(map_b));
  REQUIRE_THROWS(indexer.install_strategy(std::make_unique<IndexB>(map_b)));

  {
    REQUIRE(indexer.get_strategy<IndexA>(name_a) != nullptr);
    REQUIRE(indexer.get_strategy<IndexB>(name_b) != nullptr);

    REQUIRE(indexer.get_strategy<IndexA>(name_b) == nullptr);
    REQUIRE(indexer.get_strategy<IndexB>(name_a) == nullptr);
  }

  while (indexer.tick() || !fetcher.requested.empty())
  {
    // Do the fetch, simulating an asynchronous fetch by the historical query
    // system
    for (auto seqno : fetcher.requested)
    {
      REQUIRE(consensus->replica.size() >= seqno);
      const auto& entry = std::get<1>(consensus->replica[seqno - 1]);
      fetcher.fetched_stores[seqno] =
        fetcher.deserialise_transaction(seqno, entry->data(), entry->size());
    }
    fetcher.requested.clear();
  }

  {
    auto index_b = indexer.get_strategy<IndexB>(name_b);
    REQUIRE(index_b != nullptr);

    check_seqnos(seqnos_1, index_b->get_write_txs(1));
    check_seqnos(seqnos_2, index_b->get_write_txs(2));
  }

  {
    INFO("Both indexes continue to be updated with new entries");
    create_transactions(
      kv_store, seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2, 100);

    auto index_a = indexer.get_strategy<IndexA>(name_a);
    REQUIRE(index_a != nullptr);

    check_seqnos(seqnos_hello, index_a->get_write_txs("hello"));
    check_seqnos(seqnos_saluton, index_a->get_write_txs("saluton"));

    auto index_b = indexer.get_strategy<IndexB>(name_b);
    REQUIRE(index_b != nullptr);

    check_seqnos(seqnos_1, index_b->get_write_txs(1));
    check_seqnos(seqnos_2, index_b->get_write_txs(2));
  }
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

// Uses the real classes, to test their interaction with indexing
TEST_CASE("integrated indexing")
{
  kv::Store kv_store;

  auto ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  kv_store.set_encryptor(std::make_shared<ccf::NodeEncryptor>(ledger_secrets));

  auto stub_writer = std::make_shared<StubWriter>();
  ccf::historical::StateCacheImpl cache(kv_store, ledger_secrets, stub_writer);

  ccf::indexing::HistoricalTransactionFetcher fetcher(cache);
  ccf::indexing::Indexer indexer(fetcher);

  // TODO: Move this after the setup transactions, once historical fetching
  // works
  const auto name_a = indexer.install_strategy(std::make_unique<IndexA>(map_a));

  // TODO: Real Raft?
  auto consensus = std::make_shared<IndexingConsensus>(indexer);
  kv_store.set_consensus(consensus);

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

  SeqNoVec seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2;

  for (size_t i = 0; i < 3; ++i)
  {
    create_transactions(
      kv_store, seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2, 10);
    rekey(kv_store, ledger_secrets);
  }

  {
    INFO("Confirm that pre-existing strategy was populated already");

    auto index_a = indexer.get_strategy<IndexA>(name_a);
    REQUIRE(index_a != nullptr);

    check_seqnos(seqnos_hello, index_a->get_write_txs("hello"));
    check_seqnos(seqnos_saluton, index_a->get_write_txs("saluton"));
  }

  INFO(
    "Indexes can be installed later, and will be populated after enough "
    "ticks");

  const auto name_b = indexer.install_strategy(std::make_unique<IndexB>(map_b));

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
        REQUIRE(consensus->replica.size() >= seqno);
        REQUIRE(seqno > 0);
        const auto& entry = std::get<1>(consensus->replica[seqno - 1]);
        combined.insert(combined.end(), entry->begin(), entry->end());
      }
      cache.handle_ledger_entries(from_seqno, to_seqno, combined);
    }

    handled_writes = writes.end() - writes.begin();

    if (loops++ > 100)
    {
      throw std::logic_error("Looks like a permanent loop");
    }
  }

  {
    auto index_b = indexer.get_strategy<IndexB>(name_b);
    REQUIRE(index_b != nullptr);

    check_seqnos(seqnos_1, index_b->get_write_txs(1));
    check_seqnos(seqnos_2, index_b->get_write_txs(2));
  }
}
