// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "kv/kv_types.h"
#include "kv/new_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/entities.h"
#include "node/network_state.h"
#include "node/new_ledger_secrets.h"

#include <doctest/doctest.h>
#include <random>
#include <string>

using StringString = kv::Map<std::string, std::string>;
using NodeEncryptor = kv::NewTxEncryptor<ccf::LedgerSecretsAccessor>;

void commit_one(kv::Store& store, StringString& map)
{
  auto tx = store.create_tx();
  auto view = tx.get_view(map);
  view->put("key", "value");
  REQUIRE(tx.commit() == kv::CommitSuccess::OK);
}

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

bool corrupt_serialised_tx(
  std::vector<uint8_t>& serialised_tx, std::vector<uint8_t>& value_to_corrupt)
{
  // This utility function corrupts a serialised transaction by changing one
  // byte of the public domain as specified by value_to_corrupt.
  std::vector<uint8_t> match_buffer;
  for (auto& i : serialised_tx)
  {
    if (i == value_to_corrupt[match_buffer.size()])
    {
      match_buffer.push_back(i);
      if (match_buffer.size() == value_to_corrupt.size())
      {
        i = 'X';
        LOG_DEBUG_FMT("Corrupting serialised public data");
        return true;
      }
    }
    else
    {
      match_buffer.clear();
    }
  }
  return false;
}

TEST_CASE("Simple encryption/decryption" * doctest::test_suite("encryption"))
{
  ccf::NetworkState network;
  uint64_t node_id = 0;
  auto ledger_secrets = std::make_shared<ccf::LedgerSecretsAccessor>(
    network.secrets, std::make_unique<ccf::NewLedgerSecrets>(), node_id);
  ledger_secrets->init();
  NodeEncryptor encryptor(ledger_secrets);

  std::vector<uint8_t> plain(10, 0x42);

  // Cannot encrypt before the very first KV version (i.e. 1)
  REQUIRE_THROWS_AS(encrypt_round_trip(encryptor, plain, 0), std::logic_error);

  REQUIRE(encrypt_round_trip(encryptor, plain, 1));
  REQUIRE(encrypt_round_trip(encryptor, plain, 2));

  ledger_secrets->set_encryption_key_for(
    3, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));
  REQUIRE(encrypt_round_trip(encryptor, plain, 1));
  REQUIRE(encrypt_round_trip(encryptor, plain, 2));
  REQUIRE(encrypt_round_trip(encryptor, plain, 3));
  REQUIRE(encrypt_round_trip(encryptor, plain, 4));

  ledger_secrets->set_encryption_key_for(
    5, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));
  REQUIRE(encrypt_round_trip(encryptor, plain, 1));
  REQUIRE(encrypt_round_trip(encryptor, plain, 2));
  REQUIRE(encrypt_round_trip(encryptor, plain, 3));
  REQUIRE(encrypt_round_trip(encryptor, plain, 4));
  REQUIRE(encrypt_round_trip(encryptor, plain, 5));
  REQUIRE(encrypt_round_trip(encryptor, plain, 6));
}

TEST_CASE("Subsequent ciphers from same plaintext are different")
{
  ccf::NetworkState network;
  uint64_t node_id = 0;
  auto ledger_secrets = std::make_shared<ccf::LedgerSecretsAccessor>(
    network.secrets, std::make_unique<ccf::NewLedgerSecrets>(), node_id);
  ledger_secrets->init();
  NodeEncryptor encryptor(ledger_secrets);

  std::vector<uint8_t> plain(128, 0x42);
  std::vector<uint8_t> cipher;
  std::vector<uint8_t> cipher2;
  std::vector<uint8_t> serialised_header;
  std::vector<uint8_t> serialised_header2;
  std::vector<uint8_t> additional_data; // No additional data
  kv::Version version = 10;
  kv::Term term = 1;

  encryptor.encrypt(
    plain, additional_data, serialised_header, cipher, version, term);

  version++;
  encryptor.encrypt(
    plain, additional_data, serialised_header2, cipher2, version, term);

  // Ciphers are different because IV is different
  REQUIRE(cipher != cipher2);
  REQUIRE(serialised_header != serialised_header2);
}

TEST_CASE("Ciphers at same seqno with different terms are different")
{
  ccf::NetworkState network;
  uint64_t node_id = 0;
  auto ledger_secrets = std::make_shared<ccf::LedgerSecretsAccessor>(
    network.secrets, std::make_unique<ccf::NewLedgerSecrets>(), node_id);
  ledger_secrets->init();
  NodeEncryptor encryptor(ledger_secrets);

  std::vector<uint8_t> plain(128, 0x42);
  std::vector<uint8_t> cipher;
  std::vector<uint8_t> cipher2;
  std::vector<uint8_t> serialised_header;
  std::vector<uint8_t> serialised_header2;
  std::vector<uint8_t> additional_data; // No additional data
  kv::Version version = 10;
  kv::Term term = 1;

  encryptor.encrypt(
    plain, additional_data, serialised_header, cipher, version, term);
  term++;
  encryptor.encrypt(
    plain, additional_data, serialised_header2, cipher2, version, term);

  // Ciphers are different because IV is different
  REQUIRE(cipher != cipher2);
  REQUIRE(serialised_header != serialised_header2);
}

TEST_CASE("Ciphers at same seqno/term with and without snapshot are different")
{
  ccf::NetworkState network;
  uint64_t node_id = 0;
  auto ledger_secrets = std::make_shared<ccf::LedgerSecretsAccessor>(
    network.secrets, std::make_unique<ccf::NewLedgerSecrets>(), node_id);
  ledger_secrets->init();
  NodeEncryptor encryptor(ledger_secrets);

  std::vector<uint8_t> plain(128, 0x42);
  std::vector<uint8_t> cipher;
  std::vector<uint8_t> cipher2;
  std::vector<uint8_t> serialised_header;
  std::vector<uint8_t> serialised_header2;
  std::vector<uint8_t> additional_data; // No additional data
  kv::Version version = 10;
  kv::Term term = 1;

  bool is_snapshot = true;
  encryptor.encrypt(
    plain,
    additional_data,
    serialised_header,
    cipher,
    version,
    term,
    is_snapshot);

  is_snapshot = !is_snapshot;
  encryptor.encrypt(
    plain,
    additional_data,
    serialised_header2,
    cipher2,
    version,
    term,
    is_snapshot);

  // Ciphers are different because IV is different
  REQUIRE(cipher != cipher2);
  REQUIRE(serialised_header != serialised_header2);
}

TEST_CASE("Additional data")
{
  ccf::NetworkState network;
  uint64_t node_id = 0;
  auto ledger_secrets = std::make_shared<ccf::LedgerSecretsAccessor>(
    network.secrets, std::make_unique<ccf::NewLedgerSecrets>(), node_id);
  ledger_secrets->init();
  NodeEncryptor encryptor(ledger_secrets);

  std::vector<uint8_t> plain(128, 0x42);
  std::vector<uint8_t> cipher;
  std::vector<uint8_t> serialised_header;
  std::vector<uint8_t> additional_data(256, 0x10);
  kv::Version version = 10;
  kv::Term term = 1;

  // Encrypting plain at version 10
  encryptor.encrypt(
    plain, additional_data, serialised_header, cipher, version, term);

  // Decrypting cipher at version 10
  std::vector<uint8_t> decrypted_cipher;
  REQUIRE(encryptor.decrypt(
    cipher, additional_data, serialised_header, decrypted_cipher, version));
  REQUIRE(plain == decrypted_cipher);

  // Tampering with additional data: decryption fails
  additional_data[100] = 0xAA;
  std::vector<uint8_t> decrypted_cipher2;
  REQUIRE_FALSE(encryptor.decrypt(
    cipher, additional_data, serialised_header, decrypted_cipher2, version));

  // mbedtls 2.16+ does not produce plain text if decryption fails
  REQUIRE(decrypted_cipher2.empty());
}

TEST_CASE("KV encryption/decryption" * doctest::test_suite("encryption"))
{
  auto consensus = std::make_shared<kv::StubConsensus>();
  StringString map("map");
  kv::Store primary_store;
  kv::Store backup_store;

  ccf::NetworkState network;
  uint64_t node_id = 0;
  auto ledger_secrets = std::make_shared<ccf::LedgerSecretsAccessor>(
    network.secrets, std::make_unique<ccf::NewLedgerSecrets>(), node_id);
  ledger_secrets->init();
  NodeEncryptor encryptor(ledger_secrets);

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
    ledger_secrets->set_encryption_key_for(
      2, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));
    ledger_secrets->set_encryption_key_for(
      3, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));
    ledger_secrets->set_encryption_key_for(
      4, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));
    ledger_secrets->set_encryption_key_for(
      5, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));

    commit_one(primary_store, map);

    auto serialised_tx = consensus->get_latest_data();

    REQUIRE(
      backup_store.deserialise(*serialised_tx) == kv::DeserialiseSuccess::PASS);
  }
}

TEST_CASE("KV integrity verification")
{
  auto consensus = std::make_shared<kv::StubConsensus>();
  StringString map("map");
  kv::Store primary_store;
  kv::Store backup_store;

  ccf::NetworkState network;
  uint64_t node_id = 0;
  auto ledger_secrets = std::make_shared<ccf::LedgerSecretsAccessor>(
    network.secrets, std::make_unique<ccf::NewLedgerSecrets>(), node_id);
  ledger_secrets->init();
  auto encryptor = std::make_shared<NodeEncryptor>(ledger_secrets);

  primary_store.set_encryptor(encryptor);
  primary_store.set_consensus(consensus);
  backup_store.set_encryptor(encryptor);

  StringString public_map("public:public_map");
  StringString private_map("private_map");

  auto tx = primary_store.create_tx();
  auto [public_view, private_view] = tx.get_view(public_map, private_map);
  std::string pub_value = "pubv1";
  public_view->put("pubk1", pub_value);
  private_view->put("privk1", "privv1");
  auto rc = tx.commit();

  // Tamper with serialised public data
  auto latest_data = consensus->get_latest_data();
  REQUIRE(latest_data.has_value());
  std::vector<uint8_t> value_to_corrupt(pub_value.begin(), pub_value.end());
  REQUIRE(corrupt_serialised_tx(latest_data.value(), value_to_corrupt));

  REQUIRE(
    backup_store.deserialise(latest_data.value()) ==
    kv::DeserialiseSuccess::FAILED);
}

TEST_CASE(
  "Encryptor compaction and rollback" * doctest::test_suite("encryption"))
{
  StringString map("map");
  kv::Store store;

  ccf::NetworkState network;
  uint64_t node_id = 0;
  auto ledger_secrets = std::make_shared<ccf::LedgerSecretsAccessor>(
    network.secrets, std::make_unique<ccf::NewLedgerSecrets>(), node_id);
  ledger_secrets->init();
  auto encryptor = std::make_shared<NodeEncryptor>(ledger_secrets);
  store.set_encryptor(encryptor);

  commit_one(store, map);

  // Assumes tx at seqno 2 rekeys. Txs from seqno 3 will be encrypted with new
  // secret
  commit_one(store, map);
  ledger_secrets->set_encryption_key_for(
    3, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));

  commit_one(store, map);

  // Rollback store at seqno 1, discarding encryption key at 3
  store.rollback(1);

  commit_one(store, map);

  // Assumes tx at seqno 3 rekeys. Txs from seqno 4 will be encrypted with new
  // secret
  commit_one(store, map);
  ledger_secrets->set_encryption_key_for(
    4, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));

  commit_one(store, map);
  commit_one(store, map);

  // Assumes tx at seqno 6 rekeys. Txs from seqno 7 will be encrypted with new
  // secret
  commit_one(store, map);
  ledger_secrets->set_encryption_key_for(
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