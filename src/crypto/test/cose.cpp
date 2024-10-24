// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/crypto/cose.h"

#include "crypto/openssl/cose_verifier.h"

#include <cstdint>
#include <doctest/doctest.h>
#include <fstream>
#include <string>
#include <vector>

static const ccf::crypto::Pem cose_sign1_sample0_cert = ccf::crypto::Pem(
  "-----BEGIN PUBLIC KEY-----\n"
  "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEqv7c4eTwwUiRZ8F6b1QrcNiiSZrNc7Kj\n"
  "UM4ZZO8VzwMwQYN6kcJ9lv5rqemlr/ViQ4pZ3/XfocrnEiQQX1dJ26c7aaLnDioi\n"
  "0jRn/N6gVUxWzLXupEQDg7XNrb116oCj\n"
  "-----END PUBLIC KEY-----\n");

static const std::vector<uint8_t> cose_sign1_sample0 = {
  210, 132, 88,  125, 164, 1,   56,  34,  4,   88,  64,  97,  102, 57,  51,
  56,  98,  54,  57,  52,  101, 100, 102, 56,  51,  53,  54,  54,  57,  51,
  51,  100, 99,  50,  102, 54,  99,  100, 50,  56,  56,  56,  97,  51,  54,
  50,  98,  53,  53,  52,  49,  56,  102, 53,  100, 50,  101, 102, 100, 102,
  98,  49,  97,  57,  56,  51,  99,  56,  98,  51,  98,  54,  56,  49,  53,
  112, 99,  99,  102, 46,  103, 111, 118, 46,  109, 115, 103, 46,  116, 121,
  112, 101, 104, 112, 114, 111, 112, 111, 115, 97,  108, 118, 99,  99,  102,
  46,  103, 111, 118, 46,  109, 115, 103, 46,  99,  114, 101, 97,  116, 101,
  100, 95,  97,  116, 26,  103, 23,  114, 91,  160, 71,  112, 97,  121, 108,
  111, 97,  100, 88,  96,  181, 64,  150, 14,  237, 176, 247, 51,  37,  225,
  53,  220, 166, 180, 86,  57,  75,  24,  61,  133, 55,  59,  122, 30,  23,
  181, 189, 58,  8,   42,  162, 165, 69,  232, 145, 219, 29,  120, 107, 241,
  214, 144, 78,  125, 192, 179, 246, 102, 52,  30,  98,  127, 64,  83,  0,
  71,  61,  219, 170, 226, 134, 51,  140, 28,  36,  223, 249, 61,  113, 7,
  181, 126, 27,  133, 84,  7,   158, 114, 113, 115, 171, 215, 57,  233, 166,
  198, 159, 243, 140, 255, 152, 255, 2,   3,   126, 18};
// Function to dump bytes to a file
void dump_bytes_to_file(
  const std::vector<uint8_t>& bytes, const std::string& filename)
{
  std::ofstream file(filename, std::ios::binary);
  if (!file)
  {
    throw std::ios_base::failure("Failed to open file for writing");
  }
  file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  file.close();
}

TEST_CASE(
  "Check insertion at key in unprotected header does not affect verification")
{
  auto verifier =
    ccf::crypto::make_cose_verifier_from_key(cose_sign1_sample0_cert);
  std::span<uint8_t> payload;

  // Verify the original COSE_Sign1
  REQUIRE(verifier->verify(cose_sign1_sample0, payload));
  REQUIRE(std::string(payload.begin(), payload.end()) == "payload");

  size_t key = 42;
  auto subkey = ccf::cose::edit::pos::AtKey{43};
  std::vector<uint8_t> value = {1, 2, 3, 4};
  auto enriched_cose_sign1 = ccf::cose::edit::set_unprotected_header(
    cose_sign1_sample0, key, subkey, value);

  // Debug
  dump_bytes_to_file(enriched_cose_sign1, "enriched.bin");

  REQUIRE(verifier->verify(enriched_cose_sign1, payload));
  REQUIRE(
    enriched_cose_sign1.size() > cose_sign1_sample0.size() + value.size());
}