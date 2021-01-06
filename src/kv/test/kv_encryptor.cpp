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