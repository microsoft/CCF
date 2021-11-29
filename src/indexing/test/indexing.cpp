// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/test/stub_writer.h"
#include "indexing/historical_transaction_fetcher.h"
#include "indexing/indexer.h"
#include "indexing/seqnos_by_key.h"
#include "kv/test/stub_consensus.h"

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

std::tuple<SeqNoVec, SeqNoVec, SeqNoVec, SeqNoVec> create_transactions(
  kv::Store& kv_store,
  size_t count = ccf::indexing::Indexer::MAX_REQUESTABLE * 3)
{
  SeqNoVec seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2;

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

  return std::make_tuple(seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2);
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
  auto [seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2] =
    create_transactions(kv_store);

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
    auto
      [more_seqnos_hello, more_seqnos_saluton, more_seqnos_1, more_seqnos_2] =
        create_transactions(kv_store, 100);

    seqnos_hello.insert(
      seqnos_hello.end(), more_seqnos_hello.begin(), more_seqnos_hello.end());
    seqnos_saluton.insert(
      seqnos_saluton.end(),
      more_seqnos_saluton.begin(),
      more_seqnos_saluton.end());
    seqnos_1.insert(seqnos_1.end(), more_seqnos_1.begin(), more_seqnos_1.end());
    seqnos_2.insert(seqnos_2.end(), more_seqnos_2.begin(), more_seqnos_2.end());

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

// Uses the real classes, to test their interaction with indexing
TEST_CASE("integrated indexing")
{
  kv::Store kv_store;

  auto ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  ledger_secrets->init();
  kv_store.set_encryptor(std::make_shared<ccf::NodeEncryptor>(ledger_secrets));

  auto stub_writer = std::make_shared<StubWriter>();
  ccf::historical::StateCache cache(kv_store, ledger_secrets, stub_writer);

  ccf::indexing::HistoricalTransactionFetcher fetcher(cache);
  ccf::indexing::Indexer indexer(fetcher);

  // TODO: Real Raft?
  auto consensus = std::make_shared<IndexingConsensus>(indexer);
  kv_store.set_consensus(consensus);

  const auto name_a = indexer.install_strategy(std::make_unique<IndexA>(map_a));

  auto [seqnos_hello, seqnos_saluton, seqnos_1, seqnos_2] =
    create_transactions(kv_store);

  {
    INFO("Confirm that pre-existing strategy was populated already");

    auto index_a = indexer.get_strategy<IndexA>(name_a);
    REQUIRE(index_a != nullptr);

    check_seqnos(seqnos_hello, index_a->get_write_txs("hello"));
    check_seqnos(seqnos_saluton, index_a->get_write_txs("saluton"));
  }
}
