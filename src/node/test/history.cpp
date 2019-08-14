// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT
#include "node/history.h"

#include "enclave/appinterface.h"
#include "kv/kv.h"
#include "kv/test/stub_consensus.h"
#include "node/encryptor.h"
#include "node/entities.h"
#include "node/nodes.h"
#include "node/signatures.h"

#include <doctest/doctest.h>

extern "C"
{
#include <evercrypt/EverCrypt_AutoConfig2.h>
}

using namespace ccfapp;

class DummyConsensus : public kv::StubConsensus
{
public:
  Store* store;

  DummyConsensus(Store* store_) : store(store_) {}

  bool replicate(
    const std::vector<std::tuple<kv::Version, std::vector<uint8_t>, bool>>&
      entries) override
  {
    if (store)
    {
      REQUIRE(entries.size() == 1);
      return store->deserialise(std::get<1>(entries[0]));
    }
    return true;
  }

  kv::Term get_term() override
  {
    return 2;
  }

  kv::Version get_commit_idx() override
  {
    return 0;
  }

  kv::NodeId leader() override
  {
    return 1;
  }

  kv::NodeId id() override
  {
    return 0;
  }

  kv::Term get_term(kv::Version version) override
  {
    return 2;
  }

  bool is_leader() override
  {
    return true;
  }
};

TEST_CASE("Check signature verification")
{
  auto encryptor = std::make_shared<ccf::NullTxEncryptor>();
  Store leader_store;
  leader_store.set_encryptor(encryptor);
  auto& leader_nodes = leader_store.create<ccf::Nodes>(
    ccf::Tables::NODES, kv::SecurityDomain::PUBLIC);
  auto& leader_signatures = leader_store.create<ccf::Signatures>(
    ccf::Tables::SIGNATURES, kv::SecurityDomain::PUBLIC);

  Store follower_store;
  follower_store.set_encryptor(encryptor);
  auto& follower_nodes = follower_store.create<ccf::Nodes>(
    ccf::Tables::NODES, kv::SecurityDomain::PUBLIC);
  auto& follower_signatures = follower_store.create<ccf::Signatures>(
    ccf::Tables::SIGNATURES, kv::SecurityDomain::PUBLIC);

  auto kp = tls::make_key_pair();

  std::shared_ptr<kv::Consensus> consensus =
    std::make_shared<DummyConsensus>(&follower_store);
  leader_store.set_consensus(consensus);
  std::shared_ptr<kv::Consensus> null_consensus =
    std::make_shared<DummyConsensus>(nullptr);
  follower_store.set_consensus(null_consensus);

  std::shared_ptr<kv::TxHistory> leader_history =
    std::make_shared<ccf::MerkleTxHistory>(
      leader_store, 0, *kp, leader_signatures, leader_nodes);
  leader_store.set_history(leader_history);

  std::shared_ptr<kv::TxHistory> follower_history =
    std::make_shared<ccf::MerkleTxHistory>(
      follower_store, 1, *kp, follower_signatures, follower_nodes);
  follower_store.set_history(follower_history);

  INFO("Write certificate");
  {
    Store::Tx txs;
    auto tx = txs.get_view(leader_nodes);
    ccf::NodeInfo ni;
    ni.cert = kp->self_sign("CN=name");
    tx->put(0, ni);
    REQUIRE(txs.commit() == kv::CommitSuccess::OK);
  }

#ifndef PBFT
  INFO("Issue signature, and verify successfully on follower");
  {
    leader_history->emit_signature();
    REQUIRE(follower_store.current_version() == 2);
  }
#endif

  INFO("Issue a bogus signature, rejected by verification on the follower");
  {
    Store::Tx txs;
    auto tx = txs.get_view(leader_signatures);
    ccf::Signature bogus(0, 0);
    bogus.sig = std::vector<uint8_t>(MBEDTLS_ECDSA_MAX_LEN, 1);
    tx->put(0, bogus);
    REQUIRE(txs.commit() == kv::CommitSuccess::NO_REPLICATE);
  }
}

TEST_CASE("Check signing works across rollback")
{
  auto encryptor = std::make_shared<ccf::NullTxEncryptor>();
  Store leader_store;
  leader_store.set_encryptor(encryptor);
  auto& leader_nodes = leader_store.create<ccf::Nodes>(
    ccf::Tables::NODES, kv::SecurityDomain::PUBLIC);
  auto& leader_signatures = leader_store.create<ccf::Signatures>(
    ccf::Tables::SIGNATURES, kv::SecurityDomain::PUBLIC);

  Store follower_store;
  follower_store.set_encryptor(encryptor);
  auto& follower_nodes = follower_store.create<ccf::Nodes>(
    ccf::Tables::NODES, kv::SecurityDomain::PUBLIC);
  auto& follower_signatures = follower_store.create<ccf::Signatures>(
    ccf::Tables::SIGNATURES, kv::SecurityDomain::PUBLIC);

  auto kp = tls::make_key_pair();

  std::shared_ptr<kv::Consensus> consensus =
    std::make_shared<DummyConsensus>(&follower_store);
  leader_store.set_consensus(consensus);
  std::shared_ptr<kv::Consensus> null_consensus =
    std::make_shared<DummyConsensus>(nullptr);
  follower_store.set_consensus(null_consensus);

  std::shared_ptr<kv::TxHistory> leader_history =
    std::make_shared<ccf::MerkleTxHistory>(
      leader_store, 0, *kp, leader_signatures, leader_nodes);
  leader_store.set_history(leader_history);

  std::shared_ptr<kv::TxHistory> follower_history =
    std::make_shared<ccf::MerkleTxHistory>(
      follower_store, 1, *kp, follower_signatures, follower_nodes);
  follower_store.set_history(follower_history);

  INFO("Write certificate");
  {
    Store::Tx txs;
    auto tx = txs.get_view(leader_nodes);
    ccf::NodeInfo ni;
    ni.cert = kp->self_sign("CN=name");
    tx->put(0, ni);
    REQUIRE(txs.commit() == kv::CommitSuccess::OK);
  }

  INFO("Transaction that we will roll back");
  {
    Store::Tx txs;
    auto tx = txs.get_view(leader_nodes);
    ccf::NodeInfo ni;
    tx->put(1, ni);
    REQUIRE(txs.commit() == kv::CommitSuccess::OK);
  }

  leader_store.rollback(1);

  INFO("Issue signature, and verify successfully on follower");
  {
    leader_history->emit_signature();
    REQUIRE(follower_store.current_version() == 2);
  }
}

class CompactingConsensus : public kv::StubConsensus
{
public:
  Store* store;
  size_t count = 0;

  CompactingConsensus(Store* store_) : store(store_) {}

  bool replicate(
    const std::vector<std::tuple<kv::Version, std::vector<uint8_t>, bool>>&
      entries) override
  {
    for (auto& [version, data, committable] : entries)
    {
      count++;
      if (committable)
        store->compact(version);
    }
    return true;
  }

  kv::Term get_term() override
  {
    return 2;
  }

  kv::Version get_commit_idx() override
  {
    return 0;
  }

  kv::NodeId leader() override
  {
    return 1;
  }

  kv::NodeId id() override
  {
    return 0;
  }

  kv::Term get_term(kv::Version version) override
  {
    return 2;
  }

  bool is_leader() override
  {
    return true;
  }
};

TEST_CASE(
  "Batches containing but not ending on a committable transaction should not "
  "halt replication")
{
  Store store;
  std::shared_ptr<CompactingConsensus> consensus =
    std::make_shared<CompactingConsensus>(&store);
  store.set_consensus(consensus);

  auto& table =
    store.create<size_t, size_t>("table", kv::SecurityDomain::PUBLIC);
  auto& other_table =
    store.create<size_t, size_t>("other_table", kv::SecurityDomain::PUBLIC);

  INFO("Write first tx");
  {
    Store::Tx tx;
    auto txv = tx.get_view(table);
    txv->put(0, 1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    REQUIRE(consensus->count == 1);
  }

  INFO("Batch of two, starting with a commitable");
  {
    auto rv = store.next_version();

    Store::Tx tx;
    auto txv = tx.get_view(table);
    txv->put(0, 2);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    REQUIRE(consensus->count == 1);

    store.commit(
      rv,
      [rv, &other_table]() {
        Store::Tx txr(rv);
        auto txrv = txr.get_view(other_table);
        txrv->put(0, 1);
        return txr.commit_reserved();
      },
      true);
    REQUIRE(consensus->count == 3);
  }

  INFO("Single tx");
  {
    Store::Tx tx;
    auto txv = tx.get_view(table);
    txv->put(0, 3);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    REQUIRE(consensus->count == 4);
  }
}

class RollbackConsensus : public kv::StubConsensus
{
public:
  Store* store;
  size_t count = 0;
  kv::Version rollback_at;
  kv::Version rollback_to;

  RollbackConsensus(
    Store* store_, kv::Version rollback_at_, kv::Version rollback_to_) :
    store(store_),
    rollback_at(rollback_at_),
    rollback_to(rollback_to_)
  {}

  bool replicate(
    const std::vector<std::tuple<kv::Version, std::vector<uint8_t>, bool>>&
      entries) override
  {
    for (auto& [version, data, committable] : entries)
    {
      count++;
      if (version == rollback_at)
        store->rollback(rollback_to);
    }
    return true;
  }

  kv::Term get_term() override
  {
    return 2;
  }

  kv::Version get_commit_idx() override
  {
    return 0;
  }

  kv::NodeId leader() override
  {
    return 1;
  }

  kv::NodeId id() override
  {
    return 0;
  }

  kv::Term get_term(kv::Version version) override
  {
    return 2;
  }

  bool is_leader() override
  {
    return true;
  }
};

TEST_CASE(
  "Check that empty rollback during replicate does not cause replication halts")
{
  Store store;
  std::shared_ptr<RollbackConsensus> consensus =
    std::make_shared<RollbackConsensus>(&store, 2, 2);
  store.set_consensus(consensus);

  auto& table =
    store.create<size_t, size_t>("table", kv::SecurityDomain::PUBLIC);

  INFO("Write first tx");
  {
    Store::Tx tx;
    auto txv = tx.get_view(table);
    txv->put(0, 1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    REQUIRE(consensus->count == 1);
  }

  INFO("Write second tx, causing a rollback");
  {
    Store::Tx tx;
    auto txv = tx.get_view(table);
    txv->put(0, 2);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    REQUIRE(consensus->count == 2);
  }

  INFO("Single tx");
  {
    Store::Tx tx;
    auto txv = tx.get_view(table);
    txv->put(0, 3);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    REQUIRE(consensus->count == 3);
  }
}

TEST_CASE(
  "Check that rollback during replicate does not cause replication halts")
{
  Store store;
  std::shared_ptr<RollbackConsensus> consensus =
    std::make_shared<RollbackConsensus>(&store, 2, 1);
  store.set_consensus(consensus);

  auto& table =
    store.create<size_t, size_t>("table", kv::SecurityDomain::PUBLIC);

  INFO("Write first tx");
  {
    Store::Tx tx;
    auto txv = tx.get_view(table);
    txv->put(0, 1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    REQUIRE(consensus->count == 1);
  }

  INFO("Write second tx, causing a rollback");
  {
    Store::Tx tx;
    auto txv = tx.get_view(table);
    txv->put(0, 2);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    REQUIRE(consensus->count == 2);
  }

  INFO("Single tx");
  {
    Store::Tx tx;
    auto txv = tx.get_view(table);
    txv->put(0, 3);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    REQUIRE(consensus->count == 3);
  }
}

// We need an explicit main to initialize kremlib and EverCrypt
int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  ::EverCrypt_AutoConfig2_init();
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}
