// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "node/history.h"

#include "ccf/app_interface.h"
#include "ccf/ds/x509_time_fmt.h"
#include "ccf/service/tables/nodes.h"
#include "crypto/certs.h"
#include "crypto/openssl/hash.h"
#include "ds/internal_logger.h"
#include "kv/kv_types.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "service/tables/signatures.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#undef FAIL

#include <condition_variable>
#include <exception>
#include <mutex>
#include <thread>

using MapT = ccf::kv::Map<size_t, size_t>;

constexpr size_t certificate_validity_period_days = 365;
using namespace std::literals;
auto valid_from =
  ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);

auto valid_to = ccf::crypto::compute_cert_valid_to_string(
  valid_from, certificate_validity_period_days);

class DummyConsensus : public ccf::kv::test::StubConsensus
{
public:
  ccf::kv::Store* store;

  DummyConsensus(ccf::kv::Store* store_) : store(store_) {}

  bool replicate(const ccf::kv::BatchVector& entries, ccf::View view) override
  {
    if (store)
    {
      REQUIRE(entries.size() == 1);
      return store->deserialize(*std::get<1>(entries[0]))->apply() !=
        ccf::kv::ApplyResult::FAIL;
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

  std::optional<ccf::kv::NodeId> primary() override
  {
    return ccf::kv::test::FirstBackupNodeId;
  }

  ccf::kv::NodeId id() override
  {
    return ccf::kv::test::PrimaryNodeId;
  }
};

TEST_CASE("Check signature verification")
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  auto node_kp = ccf::crypto::make_ec_key_pair();
  auto service_kp = std::dynamic_pointer_cast<ccf::crypto::ECKeyPair_OpenSSL>(
    ccf::crypto::make_ec_key_pair());

  const auto self_signed = node_kp->self_sign("CN=Node", valid_from, valid_to);

  ccf::kv::Store primary_store;
  primary_store.set_encryptor(encryptor);
  constexpr auto store_term = 2;
  std::shared_ptr<ccf::kv::TxHistory> primary_history =
    std::make_shared<ccf::MerkleTxHistory>(
      primary_store, ccf::kv::test::PrimaryNodeId, *node_kp);
  primary_history->set_endorsed_certificate(self_signed);
  primary_history->set_service_signing_identity(
    service_kp, ccf::COSESignaturesConfig{});
  primary_store.set_history(primary_history);
  primary_store.initialise_term(store_term);

  ccf::kv::Store backup_store;
  backup_store.set_encryptor(encryptor);
  std::shared_ptr<ccf::kv::TxHistory> backup_history =
    std::make_shared<ccf::MerkleTxHistory>(
      backup_store, ccf::kv::test::FirstBackupNodeId, *node_kp);
  backup_history->set_endorsed_certificate(self_signed);
  backup_history->set_service_signing_identity(
    service_kp, ccf::COSESignaturesConfig{});
  backup_store.set_history(backup_history);
  backup_store.initialise_term(store_term);

  ccf::Nodes nodes(ccf::Tables::NODES);
  ccf::Service service(ccf::Tables::SERVICE);
  ccf::Signatures signatures(ccf::Tables::SIGNATURES);

  std::shared_ptr<ccf::kv::Consensus> consensus =
    std::make_shared<DummyConsensus>(&backup_store);
  primary_store.set_consensus(consensus);

  std::shared_ptr<ccf::kv::Consensus> null_consensus =
    std::make_shared<DummyConsensus>(nullptr);
  backup_store.set_consensus(null_consensus);

  INFO("Write certificates");
  {
    auto txs = primary_store.create_tx();
    auto tx = txs.rw(nodes);
    ccf::NodeInfo ni;
    ni.encryption_pub_key = node_kp->public_key_pem();
    ni.cert = self_signed;
    tx->put(ccf::kv::test::PrimaryNodeId, ni);

    auto stx = txs.rw(service);
    auto service_info = ccf::ServiceInfo{
      .cert = service_kp->self_sign("CN=Service", valid_from, valid_to)};
    stx->put(service_info);
    REQUIRE(txs.commit() == ccf::kv::CommitResult::SUCCESS);
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
    ccf::PrimarySignature bogus(ccf::kv::test::PrimaryNodeId, 0);
    bogus.sig = std::vector<uint8_t>(256, 1);
    sigs->put(bogus);
    REQUIRE(txs.commit() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  }
}

TEST_CASE("Check signing works across rollback")
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  auto node_kp = ccf::crypto::make_ec_key_pair();
  auto service_kp = std::dynamic_pointer_cast<ccf::crypto::ECKeyPair_OpenSSL>(
    ccf::crypto::make_ec_key_pair());

  const auto self_signed = node_kp->self_sign("CN=Node", valid_from, valid_to);

  ccf::kv::Store primary_store;
  primary_store.set_encryptor(encryptor);
  constexpr auto store_term = 2;
  std::shared_ptr<ccf::kv::TxHistory> primary_history =
    std::make_shared<ccf::MerkleTxHistory>(
      primary_store, ccf::kv::test::PrimaryNodeId, *node_kp);
  primary_history->set_endorsed_certificate(self_signed);
  primary_history->set_service_signing_identity(
    service_kp, ccf::COSESignaturesConfig{});
  primary_store.set_history(primary_history);
  primary_store.initialise_term(store_term);

  ccf::kv::Store backup_store;
  std::shared_ptr<ccf::kv::TxHistory> backup_history =
    std::make_shared<ccf::MerkleTxHistory>(
      backup_store, ccf::kv::test::FirstBackupNodeId, *node_kp);
  backup_history->set_endorsed_certificate(self_signed);
  backup_history->set_service_signing_identity(
    service_kp, ccf::COSESignaturesConfig{});
  backup_store.set_history(backup_history);
  backup_store.set_encryptor(encryptor);
  backup_store.initialise_term(store_term);

  ccf::Nodes nodes(ccf::Tables::NODES);
  ccf::Service service(ccf::Tables::SERVICE);

  std::shared_ptr<ccf::kv::Consensus> consensus =
    std::make_shared<DummyConsensus>(&backup_store);
  primary_store.set_consensus(consensus);
  std::shared_ptr<ccf::kv::Consensus> null_consensus =
    std::make_shared<DummyConsensus>(nullptr);
  backup_store.set_consensus(null_consensus);

  INFO("Write certificates");
  {
    auto txs = primary_store.create_tx();
    auto tx = txs.rw(nodes);
    ccf::NodeInfo ni;
    ni.encryption_pub_key = node_kp->public_key_pem();
    ni.cert = self_signed;
    tx->put(ccf::kv::test::PrimaryNodeId, ni);

    auto stx = txs.rw(service);
    auto service_info = ccf::ServiceInfo{
      .cert = service_kp->self_sign("CN=Service", valid_from, valid_to)};
    stx->put(service_info);
    REQUIRE(txs.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  auto v1_proof = primary_history->get_proof(primary_store.current_version());

  INFO("Transaction that we will roll back");
  {
    auto txs = primary_store.create_tx();
    auto tx = txs.rw(nodes);
    ccf::NodeInfo ni;
    tx->put(ccf::kv::test::FirstBackupNodeId, ni);
    REQUIRE(txs.commit() == ccf::kv::CommitResult::SUCCESS);
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

class CompactingConsensus : public ccf::kv::test::StubConsensus
{
public:
  ccf::kv::Store* store;
  size_t count = 0;

  CompactingConsensus(ccf::kv::Store* store_) : store(store_) {}

  bool replicate(const ccf::kv::BatchVector& entries, ccf::View view) override
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

  std::optional<ccf::kv::NodeId> primary() override
  {
    return ccf::kv::test::PrimaryNodeId;
  }

  ccf::kv::NodeId id() override
  {
    return ccf::kv::test::PrimaryNodeId;
  }

  ccf::View get_view(ccf::kv::Version version) override
  {
    return 2;
  }
};

class TestPendingTx : public ccf::kv::PendingTx
{
  ccf::TxID txid;
  ccf::kv::Store& store;
  MapT& other_table;

public:
  TestPendingTx(ccf::TxID txid_, ccf::kv::Store& store_, MapT& other_table_) :
    txid(txid_),
    store(store_),
    other_table(other_table_)
  {}

  ccf::kv::PendingTxInfo call() override
  {
    auto txr = store.create_reserved_tx(txid);
    auto txrv = txr.rw(other_table);
    txrv->put(0, 1);
    return txr.commit_reserved();
  }
};

struct PausedSignatureCommit
{
  std::mutex lock;
  std::condition_variable reserved_tx_created_cv;
  std::condition_variable resume_cv;
  bool reserved_tx_created = false;
  bool resume = false;
};

class PausedReservedSignatureTx : public ccf::kv::PendingTx
{
  ccf::TxID txid;
  ccf::kv::Store& store;
  ccf::Signatures signatures;
  ccf::SerialisedMerkleTree serialised_tree;
  PausedSignatureCommit& paused;

public:
  PausedReservedSignatureTx(
    ccf::TxID txid_, ccf::kv::Store& store_, PausedSignatureCommit& paused_) :
    txid(txid_),
    store(store_),
    signatures(ccf::Tables::SIGNATURES),
    serialised_tree(ccf::Tables::SERIALISED_MERKLE_TREE),
    paused(paused_)
  {}

  ccf::kv::PendingTxInfo call() override
  {
    auto tx = store.create_reserved_tx(txid);
    auto sig = tx.rw(signatures);
    auto tree = tx.rw(serialised_tree);

    sig->put(ccf::PrimarySignature(ccf::kv::test::PrimaryNodeId, txid.seqno));
    tree->put({});

    {
      std::lock_guard<std::mutex> guard(paused.lock);
      paused.reserved_tx_created = true;
    }
    paused.reserved_tx_created_cv.notify_one();

    std::unique_lock<std::mutex> guard(paused.lock);
    paused.resume_cv.wait(guard, [this]() { return paused.resume; });

    return tx.commit_reserved();
  }
};

TEST_CASE(
  "Batches containing but not ending on a committable transaction should not "
  "halt replication")
{
  ccf::kv::Store store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
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
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 1);
  }

  INFO("Batch of two, starting with a commitable");
  {
    auto rv = store.next_txid();

    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 2);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
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
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 4);
  }
}

class RollbackConsensus : public ccf::kv::test::StubConsensus
{
public:
  ccf::kv::Store* store;
  size_t count = 0;
  ccf::kv::Version rollback_at;
  ccf::kv::Version rollback_to;

  RollbackConsensus(
    ccf::kv::Store* store_,
    ccf::kv::Version rollback_at_,
    ccf::kv::Version rollback_to_) :
    store(store_),
    rollback_at(rollback_at_),
    rollback_to(rollback_to_)
  {}

  bool replicate(const ccf::kv::BatchVector& entries, ccf::View view) override
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

  std::optional<ccf::kv::NodeId> primary() override
  {
    return ccf::kv::test::PrimaryNodeId;
  }

  ccf::kv::NodeId id() override
  {
    return ccf::kv::test::PrimaryNodeId;
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
  ccf::kv::Store store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
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
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 1);
  }

  INFO("Write second tx, causing a rollback");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 2);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 2);
  }

  INFO("Single tx");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 3);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 3);
  }
}

TEST_CASE(
  "Reserved signature tx returns no-replicate if rolled back before "
  "commit_reserved")
{
  ccf::kv::Store store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);
  auto consensus = std::make_shared<ccf::kv::test::PrimaryStubConsensus>();
  store.set_consensus(consensus);
  constexpr auto store_term = 2;
  store.initialise_term(store_term);

  MapT table("public:table");

  INFO("Commit two normal transactions before emitting a signature");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 1);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 2);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  REQUIRE(store.current_version() == 2);

  auto txid = store.next_txid();
  REQUIRE(txid == ccf::TxID(store_term, 3));

  PausedSignatureCommit paused;
  std::optional<ccf::kv::CommitResult> worker_result;

  std::thread worker([&]() {
    worker_result = store.commit(
      txid,
      std::make_unique<PausedReservedSignatureTx>(txid, store, paused),
      true);
  });

  {
    std::unique_lock<std::mutex> guard(paused.lock);
    paused.reserved_tx_created_cv.wait(
      guard, [&paused]() { return paused.reserved_tx_created; });
  }

  const auto new_term = store_term + 1;

  INFO(
    "Rollback after create_reserved_tx but before commit_reserved in a new "
    "term");
  store.rollback({store_term, 1}, new_term);
  REQUIRE(store.commit_view() == new_term);

  {
    std::lock_guard<std::mutex> guard(paused.lock);
    paused.resume = true;
  }
  paused.resume_cv.notify_one();
  worker.join();

  REQUIRE(worker_result.has_value());
  REQUIRE(worker_result.value() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  REQUIRE(consensus->number_of_replicas() == 2);

  INFO("A normal transaction can still commit after the failed signature path");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 3);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  REQUIRE(store.current_txid() == ccf::TxID(new_term, 2));
  REQUIRE(consensus->number_of_replicas() == 3);
}

TEST_CASE(
  "Check that rollback during replicate does not cause replication halts")
{
  ccf::kv::Store store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
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
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 1);
  }

  INFO("Write second tx, causing a rollback");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 2);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 2);
  }

  INFO("Single tx");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 3);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
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
