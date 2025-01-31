// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/logger.h"
#include "ccf/pal/snp_ioctl.h"
#include "ccf/pal/snp_ioctl5.h"
#include "ccf/pal/snp_ioctl6.h"

#include "ccf/pal/report_data.h"

#include "crypto/openssl/hash.h"

#include "ccf/crypto/symmetric_key.h"

//#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#include <random>
#include <string>

#include <span>

TEST_CASE("SNP derive key")
{
  auto key1 = ccf::pal::snp::ioctl6::DerivedKey().get();
  LOG_INFO_FMT("Key1: {}", ccf::ds::to_hex(key1));
  auto key2 = ccf::pal::snp::ioctl6::DerivedKey().get();
  LOG_INFO_FMT("Key2: {}", ccf::ds::to_hex(key2));

  std::vector<uint8_t> expected_plaintext = {0xde, 0xad, 0xbe, 0xef};
  auto ciphertext = ccf::crypto::aes_gcm_encrypt(key1, expected_plaintext);
  auto decrypted_plaintext = ccf::crypto::aes_gcm_decrypt(key2, ciphertext);

  CHECK_EQ(ccf::ds::to_hex(expected_plaintext), ccf::ds::to_hex(decrypted_plaintext));
}

int main(int argc, char** argv)
{
	//ccf::logger::config::loggers().emplace_back(std::make_unique<ccf::logger::TextConsoleLogger>());

  ccf::crypto::openssl_sha256_init();
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  ccf::crypto::openssl_sha256_shutdown();
	return res;
}
