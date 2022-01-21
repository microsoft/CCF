// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/indexing/seqnos_by_key.h"
#include "indexing/indexer.h"
#include "kv/test/stub_consensus.h"

// Needed by TestTransactionFetcher
#include "kv/test/null_encryptor.h"

using MapA = kv::Map<std::string, std::string>;
using MapB = kv::Map<size_t, size_t>;
static kv::Map<std::string, std::string> map_a("private_map_a");
using IndexA = ccf::indexing::strategies::SeqnosByKey<decltype(map_a)>;
using LazyIndexA = ccf::indexing::LazyStrategy<IndexA>;

static kv::Map<size_t, size_t> map_b("private_map_b");
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

template <typename TConsensus>
class AllCommittableWrapper : public TConsensus
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

using AllCommittableConsensus = AllCommittableWrapper<kv::test::StubConsensus>;

using ExpectedSeqNos = std::set<ccf::SeqNo>;

static inline bool check_seqnos(
  const ExpectedSeqNos& expected,
  const std::optional<ccf::indexing::SeqNoCollection>& actual,
  bool complete_match = true)
{
  if (complete_match)
  {
    if (expected.size() != actual->size())
    {
      LOG_FAIL_FMT("{} != {}", expected.size(), actual->size());
      return false;
    }
  }
  else if (expected.size() < actual->size())
  {
    LOG_FAIL_FMT("{} < {}", expected.size(), actual->size());
    return false;
  }

  for (auto n : *actual)
  {
    if (!expected.contains(n))
    {
      LOG_FAIL_FMT("Got unexpected element {}", n);
      return false;
    }
  }

  return true;
}

static inline bool create_transactions(
  kv::Store& kv_store,
  ExpectedSeqNos& seqnos_hello,
  ExpectedSeqNos& seqnos_saluton,
  ExpectedSeqNos& seqnos_1,
  ExpectedSeqNos& seqnos_2,
  size_t count = ccf::indexing::Indexer::MAX_REQUESTABLE * 3)
{
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

    if (tx.commit() != kv::CommitResult::SUCCESS)
    {
      return false;
    }

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

  return true;
}
