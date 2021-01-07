// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/logger.h"
#include "kv/kv_serialiser.h"
#include "kv/new_encryptor.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "kv/tx.h"

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

void commit_one(kv::Store& store, MapTypes::StringString& map)
{
  auto tx = store.create_tx();
  auto view = tx.get_view(map);
  view->put("key", "value");
  REQUIRE(tx.commit() == kv::CommitSuccess::OK);
}

TEST_CASE("Simple encryption/decryption")
{
  kv::NewTxEncryptor encryptor(
    tls::create_entropy()->random(crypto::GCM_SIZE_KEY));

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

  auto encryption_key_at_one =
    tls::create_entropy()->random(crypto::GCM_SIZE_KEY);
  auto primary_encryptor =
    std::make_shared<kv::NewTxEncryptor>(encryption_key_at_one);
  auto backup_encryptor =
    std::make_shared<kv::NewTxEncryptor>(encryption_key_at_one);

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

// TODO: Finish writing this test case
TEST_CASE("Encryptor compaction and rollback")
{
  MapTypes::StringString map("map");

  kv::Store store;

  auto encryptor = std::make_shared<kv::NewTxEncryptor>(
    tls::create_entropy()->random(crypto::GCM_SIZE_KEY));
  store.set_encryptor(encryptor);
  encryptor->update_encryption_key(
    2, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));

  // commit_one(store, map);
  // commit_one(store, map);

  encryptor->rollback(1);

  encryptor->update_encryption_key(
    3, tls::create_entropy()->random(crypto::GCM_SIZE_KEY));

  encryptor->compact(400);
}
