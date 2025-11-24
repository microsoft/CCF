// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "indexing/indexer.h"
#include "kv/test/stub_consensus.h"

// Needed by TestTransactionFetcher
#include "kv/test/null_encryptor.h"

using MapA = ccf::kv::Map<std::string, std::string>;
static MapA map_a("public:map_a");

using MapB = ccf::kv::Map<size_t, size_t>;
static MapB map_b("public:map_b");

using ValueA = ccf::kv::Value<std::string>;
static ValueA value_a("public:value_a");

using SetA = ccf::kv::Set<std::string>;
static SetA set_a("public:set_a");

static const std::chrono::milliseconds step_time(10);

class TestTransactionFetcher : public ccf::indexing::TransactionFetcher
{
public:
  std::shared_ptr<ccf::kv::NullTxEncryptor> encryptor =
    std::make_shared<ccf::kv::NullTxEncryptor>();

  ccf::SeqNoCollection requested;
  std::unordered_map<ccf::SeqNo, ccf::kv::ReadOnlyStorePtr> fetched_stores;

  ccf::kv::ReadOnlyStorePtr deserialise_transaction(
    ccf::SeqNo seqno, const uint8_t* data, size_t size)
  {
    auto store = std::make_shared<ccf::kv::Store>(
      false /* Do not start from very first seqno */,
      true /* Make use of historical secrets */);

    store->set_encryptor(encryptor);

    bool public_only = false;
    auto exec = store->deserialize({data, data + size}, public_only);
    if (exec == nullptr)
    {
      return nullptr;
    }

    auto result = exec->apply();
    if (result == ccf::kv::ApplyResult::FAIL)
    {
      return nullptr;
    }

    return store;
  }

  std::vector<ccf::kv::ReadOnlyStorePtr> fetch_transactions(
    const ccf::SeqNoCollection& seqnos)
  {
    std::vector<ccf::kv::ReadOnlyStorePtr> stores;

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

  bool replicate(const ccf::kv::BatchVector& entries_, ccf::View view) override
  {
    // Rather than building a history that produces real signatures, we just
    // overwrite the entries here to say that everything is committable
    ccf::kv::BatchVector entries(entries_);
    for (auto& [seqno, data, committable, hooks] : entries)
    {
      committable = true;
    }

    return TConsensus::replicate(entries, view);
  }
};

using AllCommittableConsensus =
  AllCommittableWrapper<ccf::kv::test::StubConsensus>;

using ExpectedSeqNos = std::set<ccf::SeqNo>;

static inline bool check_seqnos(
  const ExpectedSeqNos& expected,
  const std::optional<ccf::SeqNoCollection>& actual,
  bool complete_match = true)
{
  // Check that actual is a contiguous subrange of expected. May actually be a
  // perfect match, that is fine too, and required if complete_match is true
  if (!actual.has_value())
  {
    LOG_FAIL_FMT("No actual result");
    return false;
  }

  if (complete_match)
  {
    if (expected.size() != actual->size())
    {
      LOG_FAIL_FMT("{} != {}", expected.size(), actual->size());
      return false;
    }
  }

  if (actual->size() > 0)
  {
    size_t idx = 0;
    auto actual_it = actual->begin();
    auto expected_it = expected.find(*actual_it);
    while (true)
    {
      if (actual_it == actual->end())
      {
        break;
      }
      else if (expected_it == expected.end())
      {
        LOG_FAIL_FMT(
          "Too many results. Reached end of expected values at {}", idx);
        return false;
      }

      if (*actual_it != *expected_it)
      {
        LOG_FAIL_FMT(
          "Mismatch at {}th result, {} != {}", idx, *actual_it, *expected_it);
        return false;
      }

      ++idx;
      ++actual_it;
      ++expected_it;
    }
  }

  return true;
}

using Action = std::function<bool(size_t, ccf::kv::Tx&)>;
struct ActionDesc
{
  ExpectedSeqNos& expected;
  Action action;
};

static inline bool create_transactions(
  ccf::kv::Store& kv_store,
  const std::vector<ActionDesc>& actions,
  size_t count = ccf::indexing::Indexer::MAX_REQUESTABLE * 3)
{
  for (size_t i = 0; i < count; ++i)
  {
    std::vector<ExpectedSeqNos*> modified;
    auto tx = kv_store.create_tx();
    for (auto& [expected, action] : actions)
    {
      if (action(i, tx))
      {
        modified.push_back(&expected);
      }
    }

    if (tx.commit() != ccf::kv::CommitResult::SUCCESS)
    {
      return false;
    }

    const auto seqno = tx.get_txid()->seqno;

    for (auto p_exp : modified)
    {
      p_exp->insert(seqno);
    }
  }

  return true;
}
