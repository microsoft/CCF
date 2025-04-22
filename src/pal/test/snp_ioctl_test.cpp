// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/symmetric_key.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/snp_ioctl.h"
#include "crypto/openssl/hash.h"

#include <cstdint>
#include <random>
#include <span>
#include <string>

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

TEST_CASE("SNP request attestation")
{
  using namespace ccf::pal;

  SnpAttestationReportData snp_report_data;
  std::iota(
    snp_report_data.report_data.begin(), snp_report_data.report_data.end(), 0);

  PlatformAttestationReportData report_data(snp_report_data);
  snp::ioctl6::Attestation ioctl_attestation(report_data);

  const snp::Attestation& attestation = ioctl_attestation.get();

  SnpAttestationReportData attested_report_data(attestation.report_data);

  REQUIRE_EQ(snp_report_data.report_data, attested_report_data.report_data);
}

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

TEST_CASE("SNP derived keys with different TCBs should be different")
{
  using namespace ccf::pal;
  ccf::pal::snp::TcbVersion tcb1{};
  auto key1 = snp::make_derived_key(tcb1);
  ccf::pal::snp::TcbVersion tcb2{};
  tcb2.snp = 0x01;
  auto key2 = snp::make_derived_key(tcb2);

  CHECK_NE(ccf::ds::to_hex(key1->get_raw()), ccf::ds::to_hex(key2->get_raw()));

  std::vector<uint8_t> expected_plaintext = {0xde, 0xad, 0xbe, 0xef};
  bool threw = false;
  try
  {
    auto ciphertext = 
      ccf::crypto::aes_gcm_encrypt(key1->get_raw(), expected_plaintext);
    auto decrypted_plaintext =
      ccf::crypto::aes_gcm_decrypt(key2->get_raw(), ciphertext);
  } catch (...) {
    threw = true;
  }

  CHECK(threw == true);
}

TEST_CASE("Expected fail junk decryption key")
{
  auto key_raw = ccf::pal::snp::make_derived_key();;
  auto key = ccf::crypto::make_key_aes_gcm(key_raw->get_raw());
  auto junk_key = ccf::crypto::make_key_aes_gcm(std::vector<uint8_t>(key_raw->get_raw().size(), 0));
  std::vector<uint8_t> tag(ccf::crypto::GCM_SIZE_TAG);

  std::vector<uint8_t> expected_plaintext = {0xde, 0xad, 0xbe, 0xef};
  auto iv = std::vector<uint8_t>(12,0);
  std::vector<uint8_t> aad{};

  std::vector<uint8_t> ciphertext;
  key->encrypt(
    iv, expected_plaintext, aad, ciphertext, tag.data());

  std::vector<uint8_t> decrypted_plaintext;

  auto rc = junk_key->decrypt(
    iv,
    tag.data(),
    std::span<const uint8_t>(ciphertext),
    aad,
    decrypted_plaintext
  );
  CHECK_EQ(rc, false);
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
