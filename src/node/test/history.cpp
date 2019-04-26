// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT
#include "../history.h"

#include "../../enclave/appinterface.h"
#include "../../kv/kv.h"
#include "../encryptor.h"
#include "../entities.h"
#include "../nodes.h"
#include "../signatures.h"

#include <doctest/doctest.h>

extern "C" {
#include <evercrypt/EverCrypt_AutoConfig2.h>
}

using namespace ccfapp;

class DummyReplicator : public kv::Replicator
{
public:
  Store* store;

  DummyReplicator(Store* store_) : store(store_) {}

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

  tls::KeyPair kp;

  std::shared_ptr<kv::Replicator> replicator =
    std::make_shared<DummyReplicator>(&follower_store);
  leader_store.set_replicator(replicator);
  std::shared_ptr<kv::Replicator> null_replicator =
    std::make_shared<DummyReplicator>(nullptr);
  follower_store.set_replicator(null_replicator);

  std::shared_ptr<kv::TxHistory> leader_history =
    std::make_shared<ccf::MerkleTxHistory>(
      leader_store, 0, kp, leader_signatures, leader_nodes);
  leader_store.set_history(leader_history);

  std::shared_ptr<kv::TxHistory> follower_history =
    std::make_shared<ccf::MerkleTxHistory>(
      follower_store, 1, kp, follower_signatures, follower_nodes);
  follower_store.set_history(follower_history);

  INFO("Write certificate");
  {
    Store::Tx txs;
    auto tx = txs.get_view(leader_nodes);
    ccf::NodeInfo ni;
    ni.cert = kp.self_sign("CN=name");
    tx->put(0, ni);
    REQUIRE(txs.commit() == kv::CommitSuccess::OK);
  }

  INFO("Issue signature, and verify successfully on follower");
  {
    leader_history->emit_signature();
    REQUIRE(follower_store.current_version() == 2);
  }

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

  tls::KeyPair kp;

  std::shared_ptr<kv::Replicator> replicator =
    std::make_shared<DummyReplicator>(&follower_store);
  leader_store.set_replicator(replicator);
  std::shared_ptr<kv::Replicator> null_replicator =
    std::make_shared<DummyReplicator>(nullptr);
  follower_store.set_replicator(null_replicator);

  std::shared_ptr<kv::TxHistory> leader_history =
    std::make_shared<ccf::MerkleTxHistory>(
      leader_store, 0, kp, leader_signatures, leader_nodes);
  leader_store.set_history(leader_history);

  std::shared_ptr<kv::TxHistory> follower_history =
    std::make_shared<ccf::MerkleTxHistory>(
      follower_store, 1, kp, follower_signatures, follower_nodes);
  follower_store.set_history(follower_history);

  INFO("Write certificate");
  {
    Store::Tx txs;
    auto tx = txs.get_view(leader_nodes);
    ccf::NodeInfo ni;
    ni.cert = kp.self_sign("CN=name");
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
