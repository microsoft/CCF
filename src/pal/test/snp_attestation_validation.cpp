// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/hex.h"
#include "ccf/ds/quote_info.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/attestation_sev_snp.h"
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
    .endorsements = std::vector<uint8_t>(
      pal::snp::testing::milan_endorsements.begin(),
      pal::snp::testing::milan_endorsements.end()),
    .uvm_endorsements = std::nullopt,
  };

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
    .endorsements = std::vector<uint8_t>(
      pal::snp::testing::genoa_endorsements.begin(),
      pal::snp::testing::genoa_endorsements.end()),
    .uvm_endorsements = std::nullopt,
  };

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
    .endorsements = std::vector<uint8_t>(
      pal::snp::testing::genoa_endorsements.begin(),
      pal::snp::testing::genoa_endorsements.end()),
    .uvm_endorsements = std::nullopt,
  };

  pal::PlatformAttestationMeasurement measurement;
  pal::PlatformAttestationReportData report_data;

  try
  {
    pal::verify_snp_attestation_report(
      mismatched_quote, measurement, report_data);
  }
  catch (const std::logic_error& e)
  {
    const std::string what = e.what();
    CHECK(
      what.find("SEV-SNP: The root of trust public key for this attestation "
                "was not the expected one") != std::string::npos);
  }
}

TEST_CASE("Parsing of Tcb versions from strings")
{
  const auto milan_tcb_version_full =
    ccf::pal::snp::TcbVersion::from_hex("d315000000000004");
  CHECK_EQ(
    nlohmann::json(milan_tcb_version_full).dump(), "\"d315000000000004\"");

  const auto milan_tcb_version = milan_tcb_version_full.to_MilanGenoa();
  CHECK_EQ(milan_tcb_version.microcode, 0xd3);
  CHECK_EQ(milan_tcb_version.snp, 0x15);
  CHECK_EQ(milan_tcb_version.tee, 0x00);
  CHECK_EQ(milan_tcb_version.boot_loader, 0x04);

  const auto turin_tcb_version =
    ccf::pal::snp::TcbVersion::from_hex("1100000022334455").to_Turin();
  CHECK_EQ(turin_tcb_version.microcode, 0x11);
  CHECK_EQ(turin_tcb_version.snp, 0x22);
  CHECK_EQ(turin_tcb_version.tee, 0x33);
  CHECK_EQ(turin_tcb_version.boot_loader, 0x44);
  CHECK_EQ(turin_tcb_version.fmc, 0x55);
}

TEST_CASE("Parsing tcb versions from attestaion")
{
  auto milan_attestation = *reinterpret_cast<const ccf::pal::snp::Attestation*>(
    ccf::pal::snp::testing::milan_attestation.data());
  auto milan_tcb = milan_attestation.reported_tcb.to_MilanGenoa();
  CHECK_EQ(milan_tcb.microcode, 0xdb);
  CHECK_EQ(milan_tcb.snp, 0x18);
  CHECK_EQ(milan_tcb.tee, 0x00);
  CHECK_EQ(milan_tcb.boot_loader, 0x04);
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
