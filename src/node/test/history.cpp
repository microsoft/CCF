// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "node/history.h"

#include "ccf/app_interface.h"
#include "ccf/service/tables/nodes.h"
#include "kv/kv_types.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "service/tables/signatures.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#undef FAIL

std::unique_ptr<threading::ThreadMessaging>
  threading::ThreadMessaging::singleton = nullptr;
  
using MapT = kv::Map<size_t, size_t>;

constexpr size_t certificate_validity_period_days = 365;
using namespace std::literals;
auto valid_from =
  ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);

auto valid_to = crypto::compute_cert_valid_to_string(
  valid_from, certificate_validity_period_days);

class DummyConsensus : public kv::test::StubConsensus
{
public:
  kv::Store* store;

  DummyConsensus(kv::Store* store_) : store(store_) {}

  bool replicate(const kv::BatchVector& entries, ccf::View view) override
  {
    if (store)
    {
      REQUIRE(entries.size() == 1);
      return store->deserialize(*std::get<1>(entries[0]), ConsensusType::CFT)
               ->apply() != kv::ApplyResult::FAIL;
    }
    return true;
  }

  std::pair<ccf::View, ccf::SeqNo> get_committed_txid() override
  {
    return {2, 0};
  }

  ccf::SeqNo get_committed_seqno() override
  {
    return 0;
  }

  std::optional<kv::NodeId> primary() override
  {
    return kv::test::FirstBackupNodeId;
  }

  kv::NodeId id() override
  {
    return kv::test::PrimaryNodeId;
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

  auto kp = crypto::make_key_pair();

  const auto self_signed = kp->self_sign("CN=Node", valid_from, valid_to);

  std::shared_ptr<kv::Consensus> consensus =
    std::make_shared<DummyConsensus>(&backup_store);
  primary_store.set_consensus(consensus);
  std::shared_ptr<kv::Consensus> null_consensus =
    std::make_shared<DummyConsensus>(nullptr);
  backup_store.set_consensus(null_consensus);

  std::shared_ptr<kv::TxHistory> primary_history =
    std::make_shared<ccf::MerkleTxHistory>(
      primary_store, kv::test::PrimaryNodeId, *kp);
  primary_history->set_endorsed_certificate(self_signed);
  primary_store.set_history(primary_history);

  std::shared_ptr<kv::TxHistory> backup_history =
    std::make_shared<ccf::MerkleTxHistory>(
      backup_store, kv::test::FirstBackupNodeId, *kp);
  backup_history->set_endorsed_certificate(self_signed);
  backup_store.set_history(backup_history);

  INFO("Write certificate");
  {
    auto txs = primary_store.create_tx();
    auto tx = txs.rw(nodes);
    ccf::NodeInfo ni;
    ni.encryption_pub_key = kp->public_key_pem();
    ni.cert = self_signed;
    tx->put(kv::test::PrimaryNodeId, ni);
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
    auto sigs = txs.rw(signatures);
    ccf::PrimarySignature bogus(kv::test::PrimaryNodeId, 0);
    bogus.sig = std::vector<uint8_t>(256, 1);
    sigs->put(bogus);
    REQUIRE(txs.commit() == kv::CommitResult::FAIL_NO_REPLICATE);
  }
}

TEST_CASE("Check signing works across rollback")
{
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv::Store primary_store;
  primary_store.set_encryptor(encryptor);
  constexpr auto store_term = 2;
  primary_store.initialise_term(store_term);

  kv::Store backup_store;
  backup_store.set_encryptor(encryptor);
  backup_store.initialise_term(store_term);

  ccf::Nodes nodes(ccf::Tables::NODES);

  auto kp = crypto::make_key_pair();

  const auto self_signed = kp->self_sign("CN=Node", valid_from, valid_to);

  std::shared_ptr<kv::Consensus> consensus =
    std::make_shared<DummyConsensus>(&backup_store);
  primary_store.set_consensus(consensus);
  std::shared_ptr<kv::Consensus> null_consensus =
    std::make_shared<DummyConsensus>(nullptr);
  backup_store.set_consensus(null_consensus);

  std::shared_ptr<kv::TxHistory> primary_history =
    std::make_shared<ccf::MerkleTxHistory>(
      primary_store, kv::test::PrimaryNodeId, *kp);
  primary_history->set_endorsed_certificate(self_signed);
  primary_store.set_history(primary_history);

  std::shared_ptr<kv::TxHistory> backup_history =
    std::make_shared<ccf::MerkleTxHistory>(
      backup_store, kv::test::FirstBackupNodeId, *kp);
  backup_history->set_endorsed_certificate(self_signed);
  backup_store.set_history(backup_history);

  INFO("Write certificate");
  {
    auto txs = primary_store.create_tx();
    auto tx = txs.rw(nodes);
    ccf::NodeInfo ni;
    ni.encryption_pub_key = kp->public_key_pem();
    ni.cert = self_signed;
    tx->put(kv::test::PrimaryNodeId, ni);
    REQUIRE(txs.commit() == kv::CommitResult::SUCCESS);
  }

  auto v1_proof = primary_history->get_proof(primary_store.current_version());

  INFO("Transaction that we will roll back");
  {
    auto txs = primary_store.create_tx();
    auto tx = txs.rw(nodes);
    ccf::NodeInfo ni;
    tx->put(kv::test::FirstBackupNodeId, ni);
    REQUIRE(txs.commit() == kv::CommitResult::SUCCESS);
  }

  primary_store.rollback({store_term, 1}, primary_store.commit_view());

  INFO("Issue signature, and verify successfully on backup");
  {
    primary_history->emit_signature();
    REQUIRE(backup_store.current_version() == 2);
  }

  auto v2_proof = primary_history->get_proof(primary_store.current_version());

  INFO("Check that past & current proofs are ok");
  {
    REQUIRE(primary_history->verify_proof(v1_proof));
    REQUIRE(primary_history->verify_proof(v2_proof));
    REQUIRE(primary_history->verify_proof(primary_history->get_proof(1)));
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

class CompactingConsensus : public kv::test::StubConsensus
{
public:
  kv::Store* store;
  size_t count = 0;

  CompactingConsensus(kv::Store* store_) : store(store_) {}

  bool replicate(const kv::BatchVector& entries, ccf::View view) override
  {
    for (auto& [version, data, committable, hooks] : entries)
    {
      count++;
      if (committable)
        store->compact(version);
    }
    return true;
  }

  std::pair<ccf::View, ccf::SeqNo> get_committed_txid() override
  {
    return {2, 0};
  }

  ccf::SeqNo get_committed_seqno() override
  {
    return 0;
  }

  std::optional<kv::NodeId> primary() override
  {
    return kv::test::PrimaryNodeId;
  }

  kv::NodeId id() override
  {
    return kv::test::PrimaryNodeId;
  }

  ccf::View get_view(kv::Version version) override
  {
    return 2;
  }
};

class TestPendingTx : public kv::PendingTx
{
  ccf::TxID txid;
  kv::Store& store;
  MapT& other_table;

public:
  TestPendingTx(ccf::TxID txid_, kv::Store& store_, MapT& other_table_) :
    txid(txid_),
    store(store_),
    other_table(other_table_)
  {}

  kv::PendingTxInfo call() override
  {
    auto txr = store.create_reserved_tx(txid);
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
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);
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

class RollbackConsensus : public kv::test::StubConsensus
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

  bool replicate(const kv::BatchVector& entries, ccf::View view) override
  {
    for (auto& [version, data, committable, hook] : entries)
    {
      count++;
      if (version == rollback_at)
        store->rollback({view, rollback_to}, store->commit_view());
    }
    return true;
  }

  std::pair<ccf::View, ccf::SeqNo> get_committed_txid() override
  {
    return {2, 0};
  }

  ccf::SeqNo get_committed_seqno() override
  {
    return 0;
  }

  std::optional<kv::NodeId> primary() override
  {
    return kv::test::PrimaryNodeId;
  }

  kv::NodeId id() override
  {
    return kv::test::PrimaryNodeId;
  }

  ccf::View get_view(ccf::SeqNo seqno) override
  {
    return 2;
  }

  ccf::View get_view() override
  {
    return 2;
  }
};

TEST_CASE(
  "Check that empty rollback during replicate does not cause replication halts")
{
  kv::Store store;
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);
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
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);
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
