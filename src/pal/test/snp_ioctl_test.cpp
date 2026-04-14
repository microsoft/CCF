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
  auto entropy = ccf::crypto::get_entropy();
  auto iv = entropy->random(ccf::crypto::iv_size);

  auto k1 = ccf::crypto::make_key_aes_gcm(key1->get_raw());
  std::vector<uint8_t> cipher;
  uint8_t tag[ccf::crypto::GCM_SIZE_TAG];
  k1->encrypt(iv, expected_plaintext, {}, cipher, tag);

  auto k2 = ccf::crypto::make_key_aes_gcm(key2->get_raw());
  std::vector<uint8_t> decrypted_plaintext;
  REQUIRE(k2->decrypt(iv, tag, cipher, {}, decrypted_plaintext));

  CHECK_EQ(
    ccf::ds::to_hex(expected_plaintext), ccf::ds::to_hex(decrypted_plaintext));
}

TEST_CASE("SNP derived keys with different TCBs should be different")
{
  using namespace ccf::pal;
  ccf::pal::snp::TcbVersionRaw tcb1{};
  auto key1 = snp::make_derived_key(tcb1);
  ccf::pal::snp::TcbVersionRaw tcb2 =
    ccf::pal::snp::TcbVersionRaw::from_hex("0100000000000000");
  auto key2 = snp::make_derived_key(tcb2);

  CHECK_NE(ccf::ds::to_hex(key1->get_raw()), ccf::ds::to_hex(key2->get_raw()));

  std::vector<uint8_t> expected_plaintext = {0xde, 0xad, 0xbe, 0xef};
  auto entropy = ccf::crypto::get_entropy();
  auto iv = entropy->random(ccf::crypto::iv_size);

  auto k1 = ccf::crypto::make_key_aes_gcm(key1->get_raw());
  std::vector<uint8_t> cipher;
  uint8_t tag[ccf::crypto::GCM_SIZE_TAG];
  k1->encrypt(iv, expected_plaintext, {}, cipher, tag);

  auto k2 = ccf::crypto::make_key_aes_gcm(key2->get_raw());
  std::vector<uint8_t> decrypted_plaintext;
  CHECK_FALSE(k2->decrypt(iv, tag, cipher, {}, decrypted_plaintext));
}

int main(int argc, char** argv)
{
  if (!ccf::pal::snp::supports_sev_snp())
  {
    std::cout << "Skipping all tests as this is not running in SEV-SNP"
              << std::endl;
    return 0;
  }

  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  return res;
}
