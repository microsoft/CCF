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
  std::vector<QuoteEndorsemenstTestCase> test_cases{
    {.attestation = ccf::pal::snp::testing::milan_attestation,
     .servers = {{
       ccf::pal::snp::EndorsementsEndpointType::AMD,
       "kdsintf.amd.com:443",
     }},
     .expected_urls =
       {.servers =
          {
            {{{
                "kdsintf.amd.com",
                "443",
                "/vcek/v1/Milan/"
                "4ffb5cb4fd594f3fee6528fc3fb10370bb38abe89dcd5ba2cf0ab6a11df2ca"
                "282add516bef45a890a8c9f9732bdca68f9f3f16c42e846030a800295dbeb1"
                "9ba5",
                {{"blSPL", "4"},
                 {"teeSPL", "0"},
                 {"snpSPL", "24"},
                 {"ucodeSPL", "219"}},
                true, // DER
              },
              {
                "kdsintf.amd.com",
                "443",
                "/vcek/v1/Milan/cert_chain",
                {},
                true, // DER
              }}}}}},
    {.attestation = ccf::pal::snp::testing::genoa_attestation,
     .servers = {{
       ccf::pal::snp::EndorsementsEndpointType::AMD,
       "kdsintf.amd.com:443",
     }},
     .expected_urls =
       {.servers =
          {{{
              "kdsintf.amd.com",
              "443",
              "/vcek/v1/Genoa/"
              "b1e24a27bbc3a4d58090d8b89851dce3b8031544be249b9ac17132bb222b0276"
              "22347ee4d0fe4f689efdfc47a68cefc686cbb448d01436506ee1e28010cab7c"
              "0",
              {{"blSPL", "10"},
               {"teeSPL", "0"},
               {"snpSPL", "23"},
               {"ucodeSPL", "84"}},
              true, // DER
            },
            {
              "kdsintf.amd.com",
              "443",
              "/vcek/v1/Genoa/cert_chain",
              {},
              true, // DER
            }}}}},
    {.attestation = ccf::pal::snp::testing::genoa_attestation,
     .servers = {{
       ccf::pal::snp::EndorsementsEndpointType::AMD,
       "kdsintf.amd.com:443",
     }},
     .expected_urls = {
       .servers = {
         {{
            "kdsintf.amd.com",
            "443",
            "/vcek/v1/Genoa/"
            "b1e24a27bbc3a4d58090d8b89851dce3b8031544be249b9ac17132bb222b027622"
            "347ee4d0fe4f689efdfc47a68cefc686cbb448d01436506ee1e28010cab7c0",
            {{"blSPL", "10"},
             {"teeSPL", "0"},
             {"snpSPL", "23"},
             {"ucodeSPL", "84"}},
            true, // DER
          },
          {
            "kdsintf.amd.com",
            "443",
            "/vcek/v1/Genoa/cert_chain",
            {},
            true, // DER
          }}}}}};

  for (auto [attestation, servers, expected_url] : test_cases)
  {
    auto quote =
      *reinterpret_cast<const ccf::pal::snp::Attestation*>(attestation.data());
    auto config =
      ccf::pal::snp::make_endorsement_endpoint_configuration(quote, servers);
    REQUIRE_EQ(config.servers.size(), expected_url.servers.size());
    for (int i = 0; i < config.servers.size(); i++)
    {
      auto endpoints = config.servers.begin();
      std::advance(endpoints, i);
      auto expected_endpoints = expected_url.servers.begin();
      std::advance(endpoints, i);

      REQUIRE_EQ(endpoints->size(), expected_endpoints->size());
      for (int j = 0; j < endpoints->size(); j++)
      {
        auto endpoint = endpoints->begin();
        std::advance(endpoint, j);
        auto expected_endpoint = expected_endpoints->begin();
        std::advance(expected_endpoint, j);

        CHECK_EQ(endpoint->host, expected_endpoint->host);
        CHECK_EQ(endpoint->port, expected_endpoint->port);
        CHECK_EQ(endpoint->uri, expected_endpoint->uri);
        REQUIRE_EQ(endpoint->params.size(), expected_endpoint->params.size());
        for (int k = 0; k < endpoint->params.size(); k++)
        {
          auto it = endpoint->params.begin();
          std::advance(it, k);
          auto expected_it = expected_endpoint->params.begin();
          std::advance(expected_it, k);
          CHECK_EQ(it->first, expected_it->first);
          CHECK_EQ(it->second, expected_it->second);
        }
      }
    }
  }
}

TEST_CASE("Quote endorsements generation for old tcb version fails")
{
  auto old_milan_attestation =
    *reinterpret_cast<const ccf::pal::snp::Attestation*>(
      ccf::pal::snp::testing::old_milan_attestation.data());

  CHECK_EQ(old_milan_attestation.cpuid_fam_id, 0x0);
  CHECK_EQ(old_milan_attestation.cpuid_mod_id, 0x0);

  CHECK_THROWS_WITH(
    ccf::pal::snp::make_endorsement_endpoint_configuration(
      (old_milan_attestation),
      {{
        ccf::pal::snp::EndorsementsEndpointType::AMD,
        "kdsintf.amd.com:443",
      }}),
    "SEV-SNP attestation version 2 is not supported. Minimum supported version "
    "is 3");
}

int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  return res;
}
