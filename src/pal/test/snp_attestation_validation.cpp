// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.


#include "ccf/ds/hex.h"
#include "ccf/ds/quote_info.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/measurement.h"
#include "ccf/pal/report_data.h"
#include "crypto/openssl/hash.h"

#include "pal/test/snp_attestation_validation_data.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

TEST_CASE("milan validation")
{
  using namespace ccf;

  auto milan_quote_info = QuoteInfo{
    .format = QuoteFormat::amd_sev_snp_v1,
    .quote = pal::snp::testing::milan_attestation,
    // bundle of certificates
    // chip_certificate /o sev_version_certificate /o root_certificate
    // root pubkey -> root cert -> sev_version_cert (ASK?) -> chip_cert
    // sig algo of attestation sig must be ecdsa_p384_sha384
    .endorsements = std::vector<uint8_t>(pal::snp::testing::milan_endorsements.begin(),
                                         pal::snp::testing::milan_endorsements.end()),
    .uvm_endorsements = std::nullopt,
  };

  
  // Output by verify_snp_attestation_report
  pal::PlatformAttestationMeasurement measurement;
  pal::PlatformAttestationReportData report_data;

  pal::verify_snp_attestation_report(
    milan_quote_info, measurement, report_data);
}

TEST_CASE("genoa validation")
{
  using namespace ccf;

  auto genoa_quote_info = QuoteInfo{
    .format = QuoteFormat::amd_sev_snp_v1,
    .quote = pal::snp::testing::genoa_attestation,
    // bundle of certificates
    // chip_certificate /o sev_version_certificate /o root_certificate
    // root pubkey -> root cert -> sev_version_cert (ASK?) -> chip_cert
    // sig algo of attestation sig must be ecdsa_p384_sha384
    .endorsements = std::vector<uint8_t>(pal::snp::testing::genoa_endorsements.begin(),
                                         pal::snp::testing::genoa_endorsements.end()),
    .uvm_endorsements = std::nullopt,
  };

  
  // Output by verify_snp_attestation_report
  pal::PlatformAttestationMeasurement measurement;
  pal::PlatformAttestationReportData report_data;

  pal::verify_snp_attestation_report(
    genoa_quote_info, measurement, report_data);
}

TEST_CASE("Mismatched attestation and endorsements fail")
{
  using namespace ccf;

  auto mismatched_quote = QuoteInfo{
    .format = QuoteFormat::amd_sev_snp_v1,
    .quote = pal::snp::testing::milan_attestation,
    // bundle of certificates
    // chip_certificate /o sev_version_certificate /o root_certificate
    // root pubkey -> root cert -> sev_version_cert (ASK?) -> chip_cert
    // sig algo of attestation sig must be ecdsa_p384_sha384
    .endorsements = std::vector<uint8_t>(pal::snp::testing::genoa_endorsements.begin(),
                                         pal::snp::testing::genoa_endorsements.end()),
    .uvm_endorsements = std::nullopt,
  };

  
  // Output by verify_snp_attestation_report
  pal::PlatformAttestationMeasurement measurement;
  pal::PlatformAttestationReportData report_data;

  try
  {
    pal::verify_snp_attestation_report(
      mismatched_quote, measurement, report_data);
  } catch (const std::logic_error& e)
  {
    const std::string what = e.what();
    CHECK(what.find("SEV-SNP: The root of trust public key for this attestation was not the expected one") != std::string::npos);
  }
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
