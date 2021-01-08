// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/logger.h"
#include "kv/kv_serialiser.h"
#include "kv/new_encryptor.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "kv/tx.h"

// TODO : Move to node/test/encryptor.cpp
#include "node/new_ledger_secrets.h"

#include <doctest/doctest.h>

struct MapTypes
{
  using StringString = kv::Map<std::string, std::string>;
};

// TODO: Move to node_state.h
using NodeEncryptor = kv::NewTxEncryptor<ccf::NewLedgerSecrets>;

bool encrypt_round_trip(
  NodeEncryptor& encryptor, std::vector<uint8_t>& plain, kv::Version version)
{
  std::vector<uint8_t> aad;
  std::vector<uint8_t> header;
  std::vector<uint8_t> cipher(plain.size());
  std::vector<uint8_t> decrypted(plain.size());

  kv::Term term = 1;
  encryptor.encrypt(plain, aad, header, cipher, version, term);
  encryptor.decrypt(cipher, aad, header, decrypted, version);

  return plain == decrypted;
}

void commit_one(kv::Store& store, MapTypes::StringString& map)
{
  auto tx = store.create_tx();
  auto view = tx.get_view(map);
  view->put("key", "value");
  REQUIRE(tx.commit() == kv::CommitSuccess::OK);
}

TEST_CASE("Simple encryption/decryption" * doctest::test_suite("encryption"))
{
  auto ledger_secrets = std::make_shared<ccf::NewLedgerSecrets>();
  NodeEncryptor encryptor(ledger_secrets);

  std::vector<uint8_t> plain(10, 0x42);

  // Cannot encrypt before the very first KV version (i.e. 1)
  REQUIRE_THROWS_AS(encrypt_round_trip(encryptor, plain, 0), std::logic_error);

  REQUIRE(encrypt_round_trip(encryptor, plain, 1));
  REQUIRE(encrypt_round_trip(encryptor, plain, 2));

  encryptor.update_encryption_key(
    3, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));
  REQUIRE(encrypt_round_trip(encryptor, plain, 1));
  REQUIRE(encrypt_round_trip(encryptor, plain, 2));
  REQUIRE(encrypt_round_trip(encryptor, plain, 3));
  REQUIRE(encrypt_round_trip(encryptor, plain, 4));

  encryptor.update_encryption_key(
    5, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));
  REQUIRE(encrypt_round_trip(encryptor, plain, 1));
  REQUIRE(encrypt_round_trip(encryptor, plain, 2));
  REQUIRE(encrypt_round_trip(encryptor, plain, 3));
  REQUIRE(encrypt_round_trip(encryptor, plain, 4));
  REQUIRE(encrypt_round_trip(encryptor, plain, 5));
  REQUIRE(encrypt_round_trip(encryptor, plain, 6));
}

TEST_CASE("KV encryption/decryption" * doctest::test_suite("encryption"))
{
  auto consensus = std::make_shared<kv::StubConsensus>();
  MapTypes::StringString map("map");

  kv::Store primary_store;
  kv::Store backup_store;

  auto ledger_secrets = std::make_shared<ccf::NewLedgerSecrets>();

  // Primary and backup stores have access to same ledger secrets
  auto primary_encryptor = std::make_shared<NodeEncryptor>(ledger_secrets);
  auto backup_encryptor = std::make_shared<NodeEncryptor>(ledger_secrets);

  INFO("Setup stores");
  {
    primary_store.set_encryptor(primary_encryptor);
    primary_store.set_consensus(consensus);
    backup_store.set_encryptor(backup_encryptor);
  }

  commit_one(primary_store, map);

  INFO("Apply transaction to backup store");
  {
    REQUIRE(
      backup_store.deserialise(*consensus->get_latest_data()) ==
      kv::DeserialiseSuccess::PASS);
  }

  INFO("Simple rekey");
  {
    // In practice, rekey is done via local commit hooks
    primary_encryptor->update_encryption_key(
      2, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));
    primary_encryptor->update_encryption_key(
      3, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));
    primary_encryptor->update_encryption_key(
      4, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));
    primary_encryptor->update_encryption_key(
      5, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));

    commit_one(primary_store, map);

    auto serialised_tx = consensus->get_latest_data();

    REQUIRE(
      backup_store.deserialise(*serialised_tx) == kv::DeserialiseSuccess::PASS);
  }
}

// TODO: Test case would benefit from further assertions on which keys are
// present in the encryptor, once this is implemented
TEST_CASE(
  "Encryptor compaction and rollback" * doctest::test_suite("encryption"))
{
  MapTypes::StringString map("map");
  kv::Store store;

  auto ledger_secrets = std::make_shared<ccf::NewLedgerSecrets>();
  auto encryptor = std::make_shared<NodeEncryptor>(ledger_secrets);
  store.set_encryptor(encryptor);

  commit_one(store, map);

  // Assumes tx at seqno 2 rekeys. Txs from seqno 3 will be encrypted with new
  // secret
  commit_one(store, map);
  encryptor->update_encryption_key(
    3, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));

  commit_one(store, map);

  // Rollback store at seqno 1, discarding encryption key at 3
  store.rollback(1);

  commit_one(store, map);

  // Assumes tx at seqno 3 rekeys. Txs from seqno 4 will be encrypted with new
  // secret
  commit_one(store, map);
  encryptor->update_encryption_key(
    4, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));

  commit_one(store, map);
  commit_one(store, map);

  // Assumes tx at seqno 6 rekeys. Txs from seqno 7 will be encrypted with new
  // secret
  commit_one(store, map);
  encryptor->update_encryption_key(
    7, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));

  store.compact(4);
  encryptor->rollback(1); // No effect as rollback before commit point

  commit_one(store, map);

  encryptor->compact(7);

  commit_one(store, map);
  commit_one(store, map);

  store.rollback(7); // No effect as rollback unique encryption key

  commit_one(store, map);
  commit_one(store, map);
}