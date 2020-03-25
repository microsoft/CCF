// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "../encryptor.h"

#include "../../kv/kv_types.h"
#include "../entities.h"
#include "../node/ledger_secrets.h"

#include <doctest/doctest.h>
#include <random>
#include <string>

using namespace ccf;

TEST_CASE("Simple encryption/decryption")
{
  // Setting 1 ledger secret, valid for version 1+
  uint64_t node_id = 0;
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->set_secret(1, std::vector<uint8_t>(16, 0x42));
  auto encryptor = std::make_shared<ccf::RaftTxEncryptor>(node_id, secrets);

  std::vector<uint8_t> plain(128, 0x42);
  std::vector<uint8_t> cipher;
  std::vector<uint8_t> serialised_header;
  std::vector<uint8_t> additional_data; // No additional data
  kv::Version version = 10;

  // Encrypting plain at version 10
  encryptor->encrypt(
    plain, additional_data, serialised_header, cipher, version);

  // Decrypting cipher at version 10
  std::vector<uint8_t> decrypted_cipher;
  REQUIRE(encryptor->decrypt(
    cipher, additional_data, serialised_header, decrypted_cipher, version));
  REQUIRE(plain == decrypted_cipher);
}

TEST_CASE("Two ciphers from same plaintext are different - RaftTxEncryptor")
{
  uint64_t node_id = 0;
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->set_secret(1, std::vector<uint8_t>(16, 0x42));
  auto encryptor = std::make_shared<ccf::RaftTxEncryptor>(node_id, secrets);

  std::vector<uint8_t> plain(128, 0x42);
  std::vector<uint8_t> cipher;
  std::vector<uint8_t> cipher2;
  std::vector<uint8_t> serialised_header;
  std::vector<uint8_t> serialised_header2;
  std::vector<uint8_t> additional_data; // No additional data
  kv::Version version = 10;

  encryptor->encrypt(
    plain, additional_data, serialised_header, cipher, version);
  encryptor->encrypt(
    plain, additional_data, serialised_header2, cipher2, version);

  // Cipher are different because IV is different
  REQUIRE(cipher != cipher2);
  REQUIRE(serialised_header != serialised_header2);
}

TEST_CASE("Two ciphers from same plaintext are different - PbftTxEncryptor")
{
  uint64_t node_id = 0;
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->set_secret(1, std::vector<uint8_t>(16, 0x42));
  auto encryptor = std::make_shared<ccf::PbftTxEncryptor>(secrets);

  std::vector<uint8_t> plain(128, 0x42);
  std::vector<uint8_t> cipher;
  std::vector<uint8_t> cipher2;
  std::vector<uint8_t> serialised_header;
  std::vector<uint8_t> serialised_header2;
  std::vector<uint8_t> additional_data; // No additional data
  kv::Version version = 10;

  encryptor->encrypt(
    plain, additional_data, serialised_header, cipher, version);
  encryptor->set_view(1);
  encryptor->encrypt(
    plain, additional_data, serialised_header2, cipher2, version);

  // Cipher are different because IV is different
  REQUIRE(cipher != cipher2);
  REQUIRE(serialised_header != serialised_header2);
}

TEST_CASE("Additional data")
{
  // Setting 1 ledger secret, valid for version 1+
  uint64_t node_id = 0;
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->set_secret(1, std::vector<uint8_t>(16, 0x42));
  auto encryptor = std::make_shared<ccf::RaftTxEncryptor>(node_id, secrets);

  std::vector<uint8_t> plain(128, 0x42);
  std::vector<uint8_t> cipher;
  std::vector<uint8_t> serialised_header;
  std::vector<uint8_t> additional_data(256, 0x10);
  kv::Version version = 10;

  // Encrypting plain at version 10
  encryptor->encrypt(
    plain, additional_data, serialised_header, cipher, version);

  // Decrypting cipher at version 10
  std::vector<uint8_t> decrypted_cipher;
  REQUIRE(encryptor->decrypt(
    cipher, additional_data, serialised_header, decrypted_cipher, version));
  REQUIRE(plain == decrypted_cipher);

  // Tampering with additional data: decryption fails
  additional_data[100] = 0xAA;
  std::vector<uint8_t> decrypted_cipher2;
  REQUIRE_FALSE(encryptor->decrypt(
    cipher, additional_data, serialised_header, decrypted_cipher2, version));

  // mbedtls 2.16+ does not produce plain text if decryption fails
  REQUIRE(decrypted_cipher2.empty());
}

TEST_CASE("Encryption/decryption with multiple ledger secrets")
{
  // Setting 2 ledger secrets, valid from version 1 and 4
  uint64_t node_id = 0;
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->set_secret(1, std::vector<uint8_t>(16, 0x42));
  secrets->set_secret(4, std::vector<uint8_t>(16, 0x43));
  auto encryptor = std::make_shared<ccf::RaftTxEncryptor>(node_id, secrets);

  INFO("Encryption with key at version 1");
  {
    std::vector<uint8_t> plain(128, 0x42);
    std::vector<uint8_t> cipher;
    std::vector<uint8_t> decrypted_cipher;
    std::vector<uint8_t> serialised_header;
    kv::Version version = 1;
    encryptor->encrypt(plain, {}, serialised_header, cipher, version);

    // Decrypting from the version which was used for encryption should succeed
    REQUIRE(encryptor->decrypt(
      cipher, {}, serialised_header, decrypted_cipher, version));
    REQUIRE(plain == decrypted_cipher);

    // Decrypting from a version in the same version interval should also
    // succeed
    REQUIRE(encryptor->decrypt(
      cipher, {}, serialised_header, decrypted_cipher, version + 1));
    REQUIRE(plain == decrypted_cipher);

    // Decrypting from a version encrypted with a different key should fail
    REQUIRE_FALSE(encryptor->decrypt(
      cipher, {}, serialised_header, decrypted_cipher, version + 4));
  }

  INFO("Encryption with key at version 4");
  {
    std::vector<uint8_t> plain(128, 0x42);
    std::vector<uint8_t> cipher;
    std::vector<uint8_t> decrypted_cipher;
    std::vector<uint8_t> serialised_header;
    kv::Version version = 4;
    encryptor->encrypt(plain, {}, serialised_header, cipher, version);

    // Decrypting from the version which was used for encryption should succeed
    REQUIRE(encryptor->decrypt(
      cipher, {}, serialised_header, decrypted_cipher, version));
    REQUIRE(plain == decrypted_cipher);

    // Decrypting from a version in the same version interval should also
    // succeed
    REQUIRE(encryptor->decrypt(
      cipher, {}, serialised_header, decrypted_cipher, version + 1));
    REQUIRE(plain == decrypted_cipher);

    // Decrypting from a version encrypted with a different key should fail
    REQUIRE_FALSE(
      encryptor->decrypt(cipher, {}, serialised_header, decrypted_cipher, 1));
  }
}