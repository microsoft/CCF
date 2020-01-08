// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "../encryptor.h"

#include "../../kv/kvtypes.h"
#include "../entities.h"
#include "../node/ledgersecrets.h"

#include <doctest/doctest.h>
#include <random>
#include <string>

using namespace ccf;

TEST_CASE("Simple encryption/decryption")
{
  // Setting 1 NetworkSecret, valid for version 0+
  uint64_t node_id = 0;
  auto secrets = ccf::LedgerSecrets();
  auto encryptor = std::make_shared<ccf::TxEncryptor>(node_id, secrets);

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

TEST_CASE("Two ciphers from same plaintext are different")
{
  uint64_t node_id = 0;
  auto secrets = ccf::LedgerSecrets();

  auto encryptor = std::make_shared<ccf::TxEncryptor>(node_id, secrets);

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

TEST_CASE("Additional data")
{
  // Setting 1 NetworkSecret, valid for version 0+
  uint64_t node_id = 0;
  auto secrets = ccf::LedgerSecrets();
  auto encryptor = std::make_shared<ccf::TxEncryptor>(node_id, secrets);

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

TEST_CASE("Encryption/decryption with multiple network secrets")
{
  // Setting 2 Network Secrets, valid from version 0 and 4
  uint64_t node_id = 0;
  auto secrets =
    ccf::LedgerSecrets(); // Create default secrets valid from version 0
  auto new_secret =
    std::make_unique<ccf::LedgerSecret>(std::vector<uint8_t>(16, 0x1));
  secrets.get_secrets().emplace(
    4, std::move(new_secret)); // Create new secrets valid from version 4

  auto encryptor = std::make_shared<ccf::TxEncryptor>(node_id, secrets);

  INFO("Encryption with key at version 0");
  {
    std::vector<uint8_t> plain(128, 0x42);
    std::vector<uint8_t> cipher;
    std::vector<uint8_t> decrypted_cipher;
    std::vector<uint8_t> serialised_header;
    encryptor->encrypt(plain, {}, serialised_header, cipher, 0);

    // Decrypting from the version which was used for encryption should succeed
    REQUIRE(
      encryptor->decrypt(cipher, {}, serialised_header, decrypted_cipher, 0));
    REQUIRE(plain == decrypted_cipher);

    // Decrypting from a version in the same version interval should also
    // succeed
    REQUIRE(
      encryptor->decrypt(cipher, {}, serialised_header, decrypted_cipher, 3));
    REQUIRE(plain == decrypted_cipher);

    // Decrypting from a version encrypted with a different key should fail
    REQUIRE_FALSE(
      encryptor->decrypt(cipher, {}, serialised_header, decrypted_cipher, 5));
  }

  INFO("Encryption with key at version 4");
  {
    std::vector<uint8_t> plain(128, 0x42);
    std::vector<uint8_t> cipher;
    std::vector<uint8_t> decrypted_cipher;
    std::vector<uint8_t> serialised_header;
    encryptor->encrypt(plain, {}, serialised_header, cipher, 4);

    // Decrypting from the version which was used for encryption should succeed
    REQUIRE(
      encryptor->decrypt(cipher, {}, serialised_header, decrypted_cipher, 4));
    REQUIRE(plain == decrypted_cipher);

    // Decrypting from a version in the same version interval should also
    // succeed
    REQUIRE(
      encryptor->decrypt(cipher, {}, serialised_header, decrypted_cipher, 5));
    REQUIRE(plain == decrypted_cipher);

    // Decrypting from a version encrypted with a different key should fail
    REQUIRE_FALSE(
      encryptor->decrypt(cipher, {}, serialised_header, decrypted_cipher, 0));
  }
}