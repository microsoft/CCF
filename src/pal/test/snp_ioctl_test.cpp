// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/symmetric_key.h"
#include "ccf/ds/logger.h"
#include "ccf/pal/snp_ioctl.h"
#include "crypto/openssl/hash.h"

#include <random>
#include <span>
#include <string>

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

TEST_CASE("SNP derive key")
{
  using namespace ccf::pal;
  auto key1 = snp::make_derived_key();
  auto key2 = snp::make_derived_key();

  REQUIRE_EQ(
    ccf::ds::to_hex(key1->get_raw()), ccf::ds::to_hex(key2->get_raw()));

  std::vector<uint8_t> expected_plaintext = {0xde, 0xad, 0xbe, 0xef};
  auto ciphertext =
    ccf::crypto::aes_gcm_encrypt(key1->get_raw(), expected_plaintext);
  auto decrypted_plaintext =
    ccf::crypto::aes_gcm_decrypt(key2->get_raw(), ciphertext);

  CHECK_EQ(
    ccf::ds::to_hex(expected_plaintext), ccf::ds::to_hex(decrypted_plaintext));
}

int main(int argc, char** argv)
{
  ccf::crypto::openssl_sha256_init();
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  ccf::crypto::openssl_sha256_shutdown();
  return res;
}
