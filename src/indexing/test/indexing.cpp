// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "indexing/indexer.h"
#include "indexing/seqnos_by_key.h"

// Needed by TestTransactionFetcher
#include "kv/test/null_encryptor.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

class TestTransactionFetcher : public indexing::TransactionFetcher
{
public:
  // TODO: Need to use a real encryptor to test historical ledger secrets?
  std::shared_ptr<kv::NullTxEncryptor> encryptor =
    std::make_shared<kv::NullTxEncryptor>();

  indexing::StorePtr deserialise_transaction(
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

  std::vector<indexing::StorePtr> fetch_transactions(const indexing::SeqNoCollection& seqnos)
  {
    return {};
  }
};

TEST_CASE("foo")
{
  indexing::Indexer indexer(std::make_unique<TestTransactionFetcher>());

  REQUIRE_THROWS(indexer.install_strategy(nullptr));

  indexer.install_strategy(
    std::make_unique<indexing::strategies::SeqnosByKey>("hello"));

  std::vector<uint8_t> entry;
  entry.push_back(1);
  entry.push_back(2);
  entry.push_back(3);
  indexer.append_entry({0, 0}, entry.data(), entry.size());
}
