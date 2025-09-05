// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/openssl_init.h"
#include "ccf/ds/hex.h"
#include "ccf/ds/logger.h"
#include "ccf/ds/quote_info.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/measurement.h"
#include "ccf/pal/report_data.h"
#include "ccf/pal/sev_snp_cpuid.h"
#include "crypto/openssl/hash.h"
#include "pal/test/attestation.h"
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
  const auto milan_tcb_version_raw =
    ccf::pal::snp::TcbVersionRaw::from_hex("d315000000000004");
  CHECK_EQ(
    nlohmann::json(milan_tcb_version_raw).dump(), "\"d315000000000004\"");

  const auto milan_tcb_policy =
    milan_tcb_version_raw.to_policy(ccf::pal::snp::ProductName::Milan);
  CHECK_EQ(
    nlohmann::json(milan_tcb_policy),
    nlohmann::json::parse(
      "{\"boot_loader\":4,\"hexstring\":\"d315000000000004\",\"microcode\":211,"
      "\"snp\":21,\"tee\":0}"));

  const auto milan_tcb_version = milan_tcb_policy.to_milan_genoa();
  CHECK_EQ(milan_tcb_version.microcode, 0xd3);
  CHECK_EQ(milan_tcb_version.snp, 0x15);
  CHECK_EQ(milan_tcb_version.tee, 0x00);
  CHECK_EQ(milan_tcb_version.boot_loader, 0x04);

  const auto turin_tcb_policy =
    ccf::pal::snp::TcbVersionRaw::from_hex("1100000022334455")
      .to_policy(ccf::pal::snp::ProductName::Turin);
  CHECK_EQ(
    nlohmann::json(turin_tcb_policy),
    nlohmann::json::parse(
      "{\"boot_loader\":68,\"fmc\":85,\"hexstring\":\"1100000022334455\","
      "\"microcode\":17,\"snp\":34,\"tee\":51}"));

  const auto turin_tcb_version = turin_tcb_policy.to_turin();
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
  auto milan_tcb =
    milan_attestation.reported_tcb.to_policy(ccf::pal::snp::ProductName::Milan)
      .to_milan_genoa();
  CHECK_EQ(milan_tcb.microcode, 0xdb);
  CHECK_EQ(milan_tcb.snp, 0x18);
  CHECK_EQ(milan_tcb.tee, 0x00);
  CHECK_EQ(milan_tcb.boot_loader, 0x04);
}

TEST_CASE("Extracting metadata from endorsements")
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

  auto attestation = *reinterpret_cast<const pal::snp::Attestation*>(
    milan_quote_info.quote.data());

  auto certificates = ccf::crypto::split_x509_cert_bundle(std::string_view(
    reinterpret_cast<const char*>(milan_quote_info.endorsements.data()),
    milan_quote_info.endorsements.size()));

  auto chip_certificate = certificates[0];

  auto endorsed_tcb = pal::get_endorsed_tcb_from_cert(
    pal::snp::ProductName::Milan, chip_certificate);
  REQUIRE(endorsed_tcb.has_value());
  CHECK_EQ(
    nlohmann::json(endorsed_tcb.value()).dump(),
    nlohmann::json(attestation.reported_tcb).dump());

  auto endorsed_chip_id = pal::get_endorsed_chip_id_from_cert(chip_certificate);
  REQUIRE(endorsed_chip_id.has_value());
  auto printable_reported_chip_id = std::span<uint8_t>(
    attestation.chip_id, attestation.chip_id + sizeof(attestation.chip_id));
  CHECK_EQ(
    ds::to_hex(endorsed_chip_id.value()),
    ds::to_hex(printable_reported_chip_id));
}

int main(int argc, char** argv)
{
  ccf::logger::config::default_init();
  ccf::crypto::openssl_sha256_init();
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  ccf::crypto::openssl_sha256_shutdown();
  return res;
}
