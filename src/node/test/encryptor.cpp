// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "node/encryptor.h"

#include "kv/kv_types.h"
#include "node/entities.h"
#include "node/ledger_secrets.h"

#include <doctest/doctest.h>
#include <random>
#include <string>

using namespace ccf;

TEST_CASE("Simple encryption/decryption")
{
  // Setting 1 ledger secret, valid for version 1+
  uint64_t node_id = 0;
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto encryptor = std::make_shared<ccf::RaftTxEncryptor>(secrets);
  encryptor->set_iv_id(node_id);

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

TEST_CASE(
  "Subsequent ciphers from same plaintext are different - RaftTxEncryptor")
{
  uint64_t node_id = 0;
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto encryptor = std::make_shared<ccf::RaftTxEncryptor>(secrets);
  encryptor->set_iv_id(node_id);

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

TEST_CASE(
  "Different node ciphers from same plaintext are different - RaftTxEncryptor")
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto encryptor_0 = std::make_shared<ccf::RaftTxEncryptor>(secrets);
  auto encryptor_1 = std::make_shared<ccf::RaftTxEncryptor>(secrets);
  encryptor_0->set_iv_id(0);
  encryptor_1->set_iv_id(1);

  std::vector<uint8_t> plain(128, 0x42);
  std::vector<uint8_t> cipher;
  std::vector<uint8_t> cipher2;
  std::vector<uint8_t> serialised_header;
  std::vector<uint8_t> serialised_header2;
  std::vector<uint8_t> additional_data; // No additional data
  kv::Version version = 10;

  encryptor_0->encrypt(
    plain, additional_data, serialised_header, cipher, version);
  encryptor_1->encrypt(
    plain, additional_data, serialised_header2, cipher2, version);

  // Cipher are different because IV is different
  REQUIRE(cipher != cipher2);
  REQUIRE(serialised_header != serialised_header2);
}

TEST_CASE("Two ciphers from same plaintext are different - PbftTxEncryptor")
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
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
  encryptor->set_iv_id(1);
  encryptor->encrypt(
    plain, additional_data, serialised_header2, cipher2, version);

  // Cipher are different because IV is different
  REQUIRE(cipher != cipher2);
  REQUIRE(serialised_header != serialised_header2);
}

TEST_CASE("Additional data")
{
  // Setting 1 ledger secret, valid for version 1+
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto encryptor = std::make_shared<ccf::RaftTxEncryptor>(secrets);

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
  secrets->init();
  secrets->add_new_secret(4, LedgerSecret());
  auto encryptor = std::make_shared<ccf::RaftTxEncryptor>(secrets);
  encryptor->set_iv_id(node_id);

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