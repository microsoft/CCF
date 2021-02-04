// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "node/history.h"

#include "enclave/app_interface.h"
#include "kv/kv_types.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/entities.h"
#include "node/nodes.h"
#include "node/signatures.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#undef FAIL

threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> threading::ThreadMessaging::thread_count = 0;
using MapT = kv::Map<size_t, size_t>;

class DummyConsensus : public kv::StubConsensus
{
public:
  kv::Store* store;

  DummyConsensus(kv::Store* store_) : store(store_) {}

  bool replicate(const kv::BatchVector& entries, View view) override
  {
    if (store)
    {
      REQUIRE(entries.size() == 1);
      return store->apply(*std::get<1>(entries[0]), ConsensusType::CFT)
               ->execute() != kv::ApplyResult::FAIL;
    }
    return true;
  }

  std::pair<View, SeqNo> get_committed_txid() override
  {
    return {2, 0};
  }

  SeqNo get_committed_seqno() override
  {
    return 0;
  }

  kv::NodeId primary() override
  {
    return 1;
  }

  kv::NodeId id() override
  {
    return 0;
  }
};

TEST_CASE("Check signature verification")
{
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();

  kv::Store primary_store;
  primary_store.set_encryptor(encryptor);

  kv::Store backup_store;
  backup_store.set_encryptor(encryptor);

  ccf::Nodes nodes(ccf::Tables::NODES);
  ccf::Signatures signatures(ccf::Tables::SIGNATURES);

  auto kp = std::make_shared<KeyPair_mbedTLS>();

  std::shared_ptr<kv::Consensus> consensus =
    std::make_shared<DummyConsensus>(&backup_store);
  primary_store.set_consensus(consensus);
  std::shared_ptr<kv::Consensus> null_consensus =
    std::make_shared<DummyConsensus>(nullptr);
  backup_store.set_consensus(null_consensus);

  std::shared_ptr<kv::TxHistory> primary_history =
    std::make_shared<ccf::MerkleTxHistory>(primary_store, 0, *kp);
  primary_store.set_history(primary_history);

  std::shared_ptr<kv::TxHistory> backup_history =
    std::make_shared<ccf::MerkleTxHistory>(backup_store, 1, *kp);
  backup_store.set_history(backup_history);

  INFO("Write certificate");
  {
    auto txs = primary_store.create_tx();
    auto tx = txs.rw(nodes);
    ccf::NodeInfo ni;
    ni.cert = kp->self_sign("CN=name");
    tx->put(0, ni);
    REQUIRE(txs.commit() == kv::CommitResult::SUCCESS);
  }

  INFO("Issue signature, and verify successfully on backup");
  {
    primary_history->emit_signature();
    REQUIRE(backup_store.current_version() == 2);
  }

  INFO("Issue a bogus signature, rejected by verification on the backup");
  {
    auto txs = primary_store.create_tx();
    auto tx = txs.rw(signatures);
    ccf::PrimarySignature bogus(0, 0);
    bogus.sig = std::vector<uint8_t>(MBEDTLS_ECDSA_MAX_LEN, 1);
    tx->put(0, bogus);
    REQUIRE(txs.commit() == kv::CommitResult::FAIL_NO_REPLICATE);
  }
}

TEST_CASE("Check signing works across rollback")
{
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv::Store primary_store;
  primary_store.set_encryptor(encryptor);

  kv::Store backup_store;
  backup_store.set_encryptor(encryptor);

  ccf::Nodes nodes(ccf::Tables::NODES);

  auto kp = tls::make_key_pair();

  std::shared_ptr<kv::Consensus> consensus =
    std::make_shared<DummyConsensus>(&backup_store);
  primary_store.set_consensus(consensus);
  std::shared_ptr<kv::Consensus> null_consensus =
    std::make_shared<DummyConsensus>(nullptr);
  backup_store.set_consensus(null_consensus);

  std::shared_ptr<kv::TxHistory> primary_history =
    std::make_shared<ccf::MerkleTxHistory>(primary_store, 0, *kp);
  primary_store.set_history(primary_history);

  std::shared_ptr<kv::TxHistory> backup_history =
    std::make_shared<ccf::MerkleTxHistory>(backup_store, 1, *kp);
  backup_store.set_history(backup_history);

  INFO("Write certificate");
  {
    auto txs = primary_store.create_tx();
    auto tx = txs.rw(nodes);
    ccf::NodeInfo ni;
    ni.cert = kp->self_sign("CN=name");
    tx->put(0, ni);
    REQUIRE(txs.commit() == kv::CommitResult::SUCCESS);
  }

  INFO("Transaction that we will roll back");
  {
    auto txs = primary_store.create_tx();
    auto tx = txs.rw(nodes);
    ccf::NodeInfo ni;
    tx->put(1, ni);
    REQUIRE(txs.commit() == kv::CommitResult::SUCCESS);
  }

  primary_store.rollback(1);
  if (consensus->type() == ConsensusType::BFT)
  {
    backup_store.rollback(1);
  }

  INFO("Issue signature, and verify successfully on backup");
  {
    primary_history->emit_signature();
    if (consensus->type() == ConsensusType::BFT)
    {
      REQUIRE(backup_store.current_version() == 1);
    }
    else
    {
      REQUIRE(backup_store.current_version() == 2);
    }
  }

  INFO("Check merkle roots are updating");
  {
    auto primary_root = primary_history->get_replicated_state_root();
    auto pr_str = fmt::format("{}", primary_root);
    auto backup_root = backup_history->get_replicated_state_root();
    auto bk_str = fmt::format("{}", backup_root);

    REQUIRE(pr_str == bk_str);
  }
}

class CompactingConsensus : public kv::StubConsensus
{
public:
  kv::Store* store;
  size_t count = 0;

  CompactingConsensus(kv::Store* store_) : store(store_) {}

  bool replicate(const kv::BatchVector& entries, View view) override
  {
    for (auto& [version, data, committable, hooks] : entries)
    {
      count++;
      if (committable)
        store->compact(version);
    }
    return true;
  }

  std::pair<View, SeqNo> get_committed_txid() override
  {
    return {2, 0};
  }

  SeqNo get_committed_seqno() override
  {
    return 0;
  }

  kv::NodeId primary() override
  {
    return 1;
  }

  kv::NodeId id() override
  {
    return 0;
  }

  View get_view(kv::Version version) override
  {
    return 2;
  }
};

class TestPendingTx : public kv::PendingTx
{
  kv::TxID txid;
  kv::Store& store;
  MapT& other_table;

public:
  TestPendingTx(kv::TxID txid_, kv::Store& store_, MapT& other_table_) :
    txid(txid_),
    store(store_),
    other_table(other_table_)
  {}

  kv::PendingTxInfo call() override
  {
    auto txr = store.create_reserved_tx(txid.version);
    auto txrv = txr.rw(other_table);
    txrv->put(0, 1);
    return txr.commit_reserved();
  }
};

TEST_CASE(
  "Batches containing but not ending on a committable transaction should not "
  "halt replication")
{
  kv::Store store;
  std::shared_ptr<CompactingConsensus> consensus =
    std::make_shared<CompactingConsensus>(&store);
  store.set_consensus(consensus);

  MapT table("public:table");
  MapT other_table("public:other_table");

  INFO("Write first tx");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 1);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 1);
  }

  INFO("Batch of two, starting with a commitable");
  {
    auto rv = store.next_txid();

    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 2);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 1);

    store.commit(
      rv, std::make_unique<TestPendingTx>(rv, store, other_table), true);
    REQUIRE(consensus->count == 3);
  }

  INFO("Single tx");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 3);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 4);
  }
}

class RollbackConsensus : public kv::StubConsensus
{
public:
  kv::Store* store;
  size_t count = 0;
  kv::Version rollback_at;
  kv::Version rollback_to;

  RollbackConsensus(
    kv::Store* store_, kv::Version rollback_at_, kv::Version rollback_to_) :
    store(store_),
    rollback_at(rollback_at_),
    rollback_to(rollback_to_)
  {}

  bool replicate(const kv::BatchVector& entries, View view) override
  {
    for (auto& [version, data, committable, hook] : entries)
    {
      count++;
      if (version == rollback_at)
        store->rollback(rollback_to);
    }
    return true;
  }

  std::pair<View, SeqNo> get_committed_txid() override
  {
    return {2, 0};
  }

  SeqNo get_committed_seqno() override
  {
    return 0;
  }

  kv::NodeId primary() override
  {
    return 1;
  }

  kv::NodeId id() override
  {
    return 0;
  }

  View get_view(SeqNo seqno) override
  {
    return 2;
  }

  View get_view() override
  {
    return 2;
  }
};

TEST_CASE(
  "Check that empty rollback during replicate does not cause replication halts")
{
  kv::Store store;
  std::shared_ptr<RollbackConsensus> consensus =
    std::make_shared<RollbackConsensus>(&store, 2, 2);
  store.set_consensus(consensus);

  MapT table("public:table");

  INFO("Write first tx");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 1);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 1);
  }

  INFO("Write second tx, causing a rollback");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 2);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 2);
  }

  INFO("Single tx");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 3);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 3);
  }
}

TEST_CASE(
  "Check that rollback during replicate does not cause replication halts")
{
  kv::Store store;
  std::shared_ptr<RollbackConsensus> consensus =
    std::make_shared<RollbackConsensus>(&store, 2, 1);
  store.set_consensus(consensus);

  MapT table("public:table");

  INFO("Write first tx");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 1);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 1);
  }

  INFO("Write second tx, causing a rollback");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 2);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 2);
  }

  INFO("Single tx");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 3);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 3);
  }
}

int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}
