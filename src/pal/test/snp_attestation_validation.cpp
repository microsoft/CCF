// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/hex.h"
#include "ccf/ds/quote_info.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/attestation_sev_snp_endorsements.h"
#include "ccf/pal/measurement.h"
#include "ccf/pal/report_data.h"
#include "ccf/pal/sev_snp_cpuid.h"
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

struct QuoteEndorsemenstTestCase
{
  std::vector<uint8_t> attestation;
  ccf::pal::snp::EndorsementsServers servers;
  ccf::pal::snp::EndorsementEndpointsConfiguration expected_urls;
};

TEST_CASE("Quote endorsements url generation")
{
  constexpr size_t max_retries_count = 10;
  std::vector<QuoteEndorsemenstTestCase> test_cases{
    {.attestation = ccf::pal::snp::testing::genoa_attestation,
     .servers = {{
       ccf::pal::snp::EndorsementsEndpointType::Azure,
       "invalid.azure.com:12345",
     }},
     .expected_urls =
       {.servers = {{{
          .host = "invalid.azure.com",
          .port = "12345",
          .uri = "/SevSnpVM/certificates/"
                 "b1e24a27bbc3a4d58090d8b89851dce3b8031544be249b9ac17132bb2"
                 "22b027622347ee4d0fe4f689efdfc47a68cefc686cbb448d01436506e"
                 "e1e28010cab7c0/541700000000000a",
          .params =
            {
              {"api-version", "2020-10-15-preview"},
            },
          .max_retries_count = max_retries_count,
          .max_client_response_size = ccf::ds::SizeString("100mb"),
        }}}}},
    {.attestation = ccf::pal::snp::testing::milan_attestation,
     .servers = {{
       ccf::pal::snp::EndorsementsEndpointType::AMD,
       "invalid.amd.com:12345",
     }},
     .expected_urls =
       {.servers =
          {
            {{{
                .host = "invalid.amd.com",
                .port = "12345",
                .uri = "/vcek/v1/Milan/"
                       "4ffb5cb4fd594f3fee6528fc3fb10370bb38abe89dcd5ba2cf0ab6a"
                       "11df2ca282add516bef45a890a8c9f9732bdca68f9f3f16c42e8460"
                       "30a800295dbeb19ba5",
                .params =
                  {{"blSPL", "4"},
                   {"teeSPL", "0"},
                   {"snpSPL", "24"},
                   {"ucodeSPL", "219"}},
                .response_is_der = true, // DER response
                .max_retries_count = max_retries_count,
                .max_client_response_size = ccf::ds::SizeString("100mb"),
              },
              {
                .host = "invalid.amd.com",
                .port = "12345",
                .uri = "/vcek/v1/Milan/cert_chain",
                .params = {},
                .response_is_der = false, // Not DER response
                .max_retries_count = max_retries_count,
                .max_client_response_size = ccf::ds::SizeString("100mb"),
              }}}}}},
    {
      .attestation = ccf::pal::snp::testing::genoa_attestation,
      .servers = {{
        ccf::pal::snp::EndorsementsEndpointType::AMD,
        "invalid.amd.com:12345",
      }},
      .expected_urls =
        {.servers =
           {
             {{{
                 .host = "invalid.amd.com",
                 .port = "12345",
                 .uri =
                   "/vcek/v1/Genoa/"
                   "b1e24a27bbc3a4d58090d8b89851dce3b8031544be249b9ac17132b"
                   "b222b027622347ee4d0fe4f689efdfc47a68cefc686cbb448d01436"
                   "506ee1e28010cab7c0",
                 .params =
                   {{"blSPL", "10"},
                    {"teeSPL", "0"},
                    {"snpSPL", "23"},
                    {"ucodeSPL", "84"}},
                 .response_is_der = true, // DER response
                 .max_retries_count = max_retries_count,
                 .max_client_response_size = ccf::ds::SizeString("100mb"),
               },
               {
                 .host = "invalid.amd.com",
                 .port = "12345",
                 .uri = "/vcek/v1/Genoa/cert_chain",
                 .params = {},
                 .response_is_der = false, // Not DER response
                 .max_retries_count = max_retries_count,
                 .max_client_response_size = ccf::ds::SizeString("100mb"),
               }}}}},
    },
    {.attestation = ccf::pal::snp::testing::genoa_attestation,
     .servers = {{
       ccf::pal::snp::EndorsementsEndpointType::THIM,
       "invalid.thim.azure.com:12345",
     }},
     .expected_urls = {
       .servers = {{{
         .host = "invalid.thim.azure.com",
         .port = "12345",
         .uri = "/metadata/THIM/amd/certification",
         .params =
           {{"platformId",
             "b1e24a27bbc3a4d58090d8b89851dce3b8031544be249b9ac17132bb222b02762"
             "2347ee4d0fe4f689efdfc47a68cefc686cbb448d01436506ee1e28010cab7c0"},
            {"tcbVersion", "541700000000000a"}},
         .response_is_thim_json = true,
         .headers = {{"Metadata", "true"}},
         .tls = false,
         .max_retries_count = max_retries_count,
         .max_client_response_size = ccf::ds::SizeString("100mb"),
       }}}}}};

  for (auto [attestation, servers, expected_url] : test_cases)
  {
    auto quote =
      *reinterpret_cast<const ccf::pal::snp::Attestation*>(attestation.data());
    auto config =
      ccf::pal::snp::make_endorsement_endpoint_configuration(quote, servers);

    CHECK_EQ(nlohmann::json(config), nlohmann::json(expected_url));
  }
}

TEST_CASE("Quote endorsements generation for v2 attestation version fails")
{
  auto v2_milan_attestation =
    *reinterpret_cast<const ccf::pal::snp::Attestation*>(
      ccf::pal::snp::testing::v2_milan_attestation.data());

  CHECK_EQ(v2_milan_attestation.version, 2);
  CHECK_EQ(v2_milan_attestation.cpuid_fam_id, 0x0);
  CHECK_EQ(v2_milan_attestation.cpuid_mod_id, 0x0);

  CHECK_THROWS_WITH(
    ccf::pal::snp::make_endorsement_endpoint_configuration(
      (v2_milan_attestation),
      {{
        ccf::pal::snp::EndorsementsEndpointType::AMD,
        "kdsintf.amd.com:443",
      }}),
    "SEV-SNP: attestation version 2 is not supported. Minimum supported "
    "version is 3");
}

int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  return res;
}
