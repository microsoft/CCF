// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/pal/measurement.h"
#include "crypto/cbor.h"
#include "crypto/openssl/hash.h"
#include "ds/files.h"
#include "node/uvm_endorsements.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <cstdlib>
#include <doctest/doctest.h>

TEST_CASE("Check RSA Production endorsement")
{
  char* end_path = std::getenv("TEST_ENDORSEMENTS_PATH");
  REQUIRE(end_path != nullptr);

  auto endorsement = files::slurp(fmt::format("{}/rsa_test1.cose", end_path));
  REQUIRE(!endorsement.empty());

  ccf::pal::SnpAttestationMeasurement measurement(
    "02c3b0d5bf1d256fa4e3b5deefc07b55ff2f7029085ed350f60959140a1a51f1310753ba5a"
    "b2c03a0536b1c0c193af47");
  ccf::pal::PlatformAttestationMeasurement uvm_measurement(measurement);
  auto endorsements = ccf::verify_uvm_endorsements_against_roots_of_trust(
    endorsement, uvm_measurement, ccf::default_uvm_roots_of_trust);
  REQUIRE(endorsements == ccf::default_uvm_roots_of_trust[1]);

  // Only extract the endorsement descriptor, but do not verify it against
  // any roots of trust
  auto authenticated_but_not_authorized_endorsements =
    ccf::pal::verify_uvm_endorsements_descriptor(endorsement, uvm_measurement);
  REQUIRE(
    authenticated_but_not_authorized_endorsements ==
    ccf::default_uvm_roots_of_trust[1]);
}

TEST_CASE("Check ECDSA Test endorsement")
{
  char* end_path = std::getenv("TEST_ENDORSEMENTS_PATH");
  REQUIRE(end_path != nullptr);

  auto endorsement = files::slurp(fmt::format("{}/ecdsa_test1.cose", end_path));
  REQUIRE(!endorsement.empty());

  ccf::pal::SnpAttestationMeasurement measurement(
    "1b66347ceafca663690ff17ed2144b8acdee661edc5d28e69a7c85dde7ba0c3a6f9862096e"
    "8b38da7aa622ddeed75c37");
  ccf::pal::PlatformAttestationMeasurement uvm_measurement(measurement);

  std::vector<ccf::pal::UVMEndorsements> custom_roots_of_trust = {
    ccf::pal::UVMEndorsements{
      "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3."
      "6.1.4.1.311.76.59.1.5",
      "Malicious-ConfAKS-AMD-UVM",
      "1"}};
  REQUIRE_THROWS_WITH_AS(
    ccf::verify_uvm_endorsements_against_roots_of_trust(
      endorsement, uvm_measurement, custom_roots_of_trust),
    "UVM endorsements did "
    "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6."
    "1.4.1.311.76.59.1.5, feed ConfAKS-AMD-UVM, svn 1 do not match any of the "
    "known UVM roots of trust",
    std::logic_error);

  auto endorsements = ccf::verify_uvm_endorsements_against_roots_of_trust(
    endorsement, uvm_measurement, ccf::default_uvm_roots_of_trust);
  REQUIRE(endorsements == ccf::default_uvm_roots_of_trust[2]);
}

TEST_CASE("Check Test endorsement with integer SVN")
{
  char* end_path = std::getenv("TEST_ENDORSEMENTS_PATH");
  REQUIRE(end_path != nullptr);

  auto endorsement = files::slurp(fmt::format("{}/int_svn.cose", end_path));
  REQUIRE(!endorsement.empty());

  ccf::pal::SnpAttestationMeasurement measurement(
    "d0c9e2be22046e60779be88868cff64c2aa22047c15d3127ba495cee3fbc2854c5633f9da2"
    "096e6c64ae2b69bbff8082");
  ccf::pal::PlatformAttestationMeasurement uvm_measurement(measurement);

  std::vector<ccf::pal::UVMEndorsements> custom_roots_of_trust = {
    ccf::pal::UVMEndorsements{
      "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3."
      "6.1.4.1.311.76.59.1.5",
      "Malicious-ConfAKS-AMD-UVM",
      "1"}};
  REQUIRE_THROWS_WITH_AS(
    ccf::verify_uvm_endorsements_against_roots_of_trust(
      endorsement, uvm_measurement, custom_roots_of_trust),
    "UVM endorsements did "
    "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6."
    "1.4.1.311.76.59.1.2, feed ContainerPlat-AMD-UVM, svn 102 do not match any "
    "of the "
    "known UVM roots of trust",
    std::logic_error);

  auto endorsements = ccf::verify_uvm_endorsements_against_roots_of_trust(
    endorsement, uvm_measurement, ccf::default_uvm_roots_of_trust);

  REQUIRE(endorsements.did == ccf::default_uvm_roots_of_trust[1].did);
  REQUIRE(endorsements.feed == ccf::default_uvm_roots_of_trust[1].feed);
  REQUIRE(endorsements.svn == "102");
}

TEST_CASE("Check Test endorsement for UVM 0.2.9")
{
  char* end_path = std::getenv("TEST_ENDORSEMENTS_PATH");
  REQUIRE(end_path != nullptr);

  auto endorsement = files::slurp(fmt::format("{}/uvm_0.2.9.cose", end_path));
  REQUIRE(!endorsement.empty());

  ccf::pal::SnpAttestationMeasurement measurement(
    "d0c9e2be22046e60779be88868cff64c2aa22047c15d3127ba495cee3fbc2854c5633f9da2"
    "096e6c64ae2b69bbff8082");
  ccf::pal::PlatformAttestationMeasurement uvm_measurement(measurement);

  std::vector<ccf::pal::UVMEndorsements> custom_roots_of_trust = {
    ccf::pal::UVMEndorsements{
      "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3."
      "6.1.4.1.311.76.59.1.5",
      "Malicious-ConfAKS-AMD-UVM",
      "1"}};
  REQUIRE_THROWS_WITH_AS(
    ccf::verify_uvm_endorsements_against_roots_of_trust(
      endorsement, uvm_measurement, custom_roots_of_trust),
    "UVM endorsements did "
    "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6."
    "1.4.1.311.76.59.1.2, feed ContainerPlat-AMD-UVM, svn 103 do not match any "
    "of the "
    "known UVM roots of trust",
    std::logic_error);

  auto endorsements = ccf::verify_uvm_endorsements_against_roots_of_trust(
    endorsement, uvm_measurement, ccf::default_uvm_roots_of_trust);

  REQUIRE(endorsements.did == ccf::default_uvm_roots_of_trust[1].did);
  REQUIRE(endorsements.feed == ccf::default_uvm_roots_of_trust[1].feed);
  REQUIRE(endorsements.svn == "103");
}

TEST_CASE("Check Test endorsement for UVM 0.2.10")
{
  char* end_path = std::getenv("TEST_ENDORSEMENTS_PATH");
  REQUIRE(end_path != nullptr);

  auto endorsement = files::slurp(fmt::format("{}/uvm_0.2.10.cose", end_path));
  REQUIRE(!endorsement.empty());

  ccf::pal::SnpAttestationMeasurement measurement(
    "4904167aa9102a7557b97ac102469f50289d5be76036fcbb8107897ee146a6184772c4ea6e"
    "3f050a1bac6951c285bc89");
  ccf::pal::PlatformAttestationMeasurement uvm_measurement(measurement);

  std::vector<ccf::pal::UVMEndorsements> custom_roots_of_trust = {
    ccf::pal::UVMEndorsements{
      "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3."
      "6.1.4.1.311.76.59.1.2",
      "Malicious-ContainerPlat-AMD-UVM",
      "104"}};

  REQUIRE_THROWS_WITH_AS(
    ccf::verify_uvm_endorsements_against_roots_of_trust(
      endorsement, uvm_measurement, custom_roots_of_trust),
    "UVM endorsements did "
    "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6."
    "1.4.1.311.76.59.1.2, feed ContainerPlat-AMD-UVM, svn 104 do not match any "
    "of the known UVM roots of trust",
    std::logic_error);

  auto endorsements = ccf::verify_uvm_endorsements_against_roots_of_trust(
    endorsement, uvm_measurement, ccf::default_uvm_roots_of_trust);

  REQUIRE(endorsements.did == ccf::default_uvm_roots_of_trust[0].did);
  REQUIRE(endorsements.feed == ccf::default_uvm_roots_of_trust[0].feed);
  REQUIRE(endorsements.svn == "104");

  auto parsed = ccf::cbor::parse(endorsement);
  const auto& cose_sign1 = parsed->tag_at(ccf::cbor::tag::COSE_SIGN_1);
  const auto& protected_header_raw = cose_sign1->array_at(0);
  auto protected_header = ccf::cbor::parse(protected_header_raw->as_bytes());
  const auto& cwt_claims = protected_header->map_at(
    ccf::cbor::make_signed(ccf::cose::header::iana::CWT_CLAIMS));
  const auto& iat =
    cwt_claims->map_at(ccf::cbor::make_signed(ccf::cwt::header::iana::IAT));
  iat->value = ccf::cbor::Tagged{
    ccf::cbor::tag::EPOCH_DATE_TIME, ccf::cbor::make_signed(0)};

  auto protected_header_bytes = ccf::cbor::serialize(protected_header);
  protected_header_raw->value = ccf::cbor::Bytes{protected_header_bytes};
  auto invalid_iat_endorsement = ccf::cbor::serialize(parsed);

  REQUIRE_THROWS_WITH_AS(
    ccf::verify_uvm_endorsements_against_roots_of_trust(
      invalid_iat_endorsement,
      uvm_measurement,
      ccf::default_uvm_roots_of_trust),
    "CWT iat 0 in UVM endorsements is outside x5chain common validity period "
    "[20250515185703Z, 20260515185703Z]",
    ccf::cose::COSEDecodeError);
}

TEST_CASE("Check UVM roots of trust matching")
{
  ccf::pal::UVMEndorsements old{"issuer1", "subject1", "0"};
  ccf::pal::UVMEndorsements current{"issuer1", "subject1", "1"};
  ccf::pal::UVMEndorsements newer{"issuer1", "subject1", "2"};
  ccf::pal::UVMEndorsements other_issuer{"issuer2", "subject1", "2"};
  ccf::pal::UVMEndorsements other_subject{"issuer1", "subject2", "2"};

  REQUIRE(ccf::matches_uvm_roots_of_trust(current, {current}));
  REQUIRE(ccf::matches_uvm_roots_of_trust(current, {old}));
  REQUIRE_FALSE(ccf::matches_uvm_roots_of_trust(current, {newer}));

  REQUIRE_FALSE(ccf::matches_uvm_roots_of_trust(current, {other_issuer}));
  REQUIRE_FALSE(ccf::matches_uvm_roots_of_trust(current, {other_subject}));
}

int main(int argc, char** argv)
{
  ccf::logger::config::default_init();
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}