// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/logger.h"
#include "kv/kv_serialiser.h"
#include "kv/new_encryptor.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "kv/tx.h"

// TODO: TO Remove
#include "tls/base64.h"

#include <doctest/doctest.h>

// TODO: Move the whole lot to kv_serialisation.cpp
struct MapTypes
{
  using StringString = kv::Map<std::string, std::string>;
  using NumNum = kv::Map<size_t, size_t>;
  using NumString = kv::Map<size_t, std::string>;
  using StringNum = kv::Map<std::string, size_t>;
};

bool encrypt_round_trip(
  kv::NewTxEncryptor& encryptor,
  std::vector<uint8_t>& plain,
  kv::Version version)
{
  std::vector<uint8_t> aad;
  std::vector<uint8_t> header;
  std::vector<uint8_t> cipher(plain.size());
  std::vector<uint8_t> decrypted(plain.size());

  encryptor.encrypt(plain, aad, header, cipher, version);

  encryptor.decrypt(cipher, aad, header, decrypted, version);

  return plain == decrypted;
}

TEST_CASE("Simple encryption/decryption")
{
  kv::NewTxEncryptor encryptor;

  // TODO: This API sucks!
  encryptor.update_encryption_key(
    1, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));

  std::vector<uint8_t> plain(10, 0x42);
  std::vector<uint8_t> aad;
  std::vector<uint8_t> cipher(10);
  std::vector<uint8_t> header;

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

TEST_CASE("KV encryption/decryption")
{
  auto consensus = std::make_shared<kv::StubConsensus>();
  MapTypes::StringString map("map");

  kv::Store primary_store;
  kv::Store backup_store;

  auto primary_encryptor = std::make_shared<kv::NewTxEncryptor>();
  auto backup_encryptor = std::make_shared<kv::NewTxEncryptor>();

  auto ledger_secret_at_one =
    tls::create_entropy()->random(crypto::GCM_SIZE_KEY);

  INFO("Setup stores");
  {
    primary_encryptor->update_encryption_key(1, ledger_secret_at_one);
    primary_store.set_encryptor(primary_encryptor);
    primary_store.set_consensus(consensus);
    backup_store.set_encryptor(backup_encryptor);
  }

  INFO("Commit one transaction on primary store");
  {
    auto tx = primary_store.create_tx();
    auto view = tx.get_view(map);
    view->put("key", "value");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  INFO("Apply transaction to backup store");
  {
    auto serialised_tx = consensus->get_latest_data();
    REQUIRE_THROWS_AS(
      backup_store.deserialise(*serialised_tx), std::logic_error);

    backup_encryptor->update_encryption_key(1, ledger_secret_at_one);
    REQUIRE(
      backup_store.deserialise(*serialised_tx) == kv::DeserialiseSuccess::PASS);
  }

  INFO("Rekey on primary");
  {
    // In practice, rekey is done via local commit hooks
    auto ledger_secret_at_two =
      tls::create_entropy()->random(crypto::GCM_SIZE_KEY);
    primary_encryptor->update_encryption_key(2, ledger_secret_at_two);

    auto tx = primary_store.create_tx();
    auto view = tx.get_view(map);
    view->put("key", "value");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    auto serialised_tx = consensus->get_latest_data();

    REQUIRE(
      backup_store.deserialise(*serialised_tx) ==
      kv::DeserialiseSuccess::FAILED);

    backup_encryptor->update_encryption_key(2, ledger_secret_at_two);

    REQUIRE(
      backup_store.deserialise(*serialised_tx) == kv::DeserialiseSuccess::PASS);
  }
}

// TODO: How to unit test a rekey? how to get the local hook out of
// node_state.h?