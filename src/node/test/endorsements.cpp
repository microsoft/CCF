// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/openssl_init.h"
#include "ccf/pal/measurement.h"
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
  REQUIRE(endorsements == ccf::default_uvm_roots_of_trust[0]);

  // Only extract the endorsement descriptor, but do not verify it against
  // any roots of trust
  auto authenticated_but_not_authorized_endorsements =
    ccf::pal::verify_uvm_endorsements_descriptor(endorsement, uvm_measurement);
  REQUIRE(
    authenticated_but_not_authorized_endorsements ==
    ccf::default_uvm_roots_of_trust[0]);
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
  REQUIRE(endorsements == ccf::default_uvm_roots_of_trust[1]);
}

TEST_CASE("Check UVM roots of trust matching")
{
  ccf::pal::UVMEndorsements old{"issuer1", "subject1", "0"};
  ccf::pal::UVMEndorsements current{"issuer1", "subject1", "1"};
  ccf::pal::UVMEndorsements newer{"issuer1", "subject1", "2"};
  ccf::pal::UVMEndorsements other_issuer{"issuer2", "subject1", "2"};
  ccf::pal::UVMEndorsements other_subject{"issuer2", "subject1", "2"};

  REQUIRE(ccf::matches_uvm_roots_of_trust(current, {current}));
  REQUIRE(ccf::matches_uvm_roots_of_trust(current, {old}));
  REQUIRE(!ccf::matches_uvm_roots_of_trust(current, {newer}));

  REQUIRE(!ccf::matches_uvm_roots_of_trust(current, {other_issuer}));
  REQUIRE(!ccf::matches_uvm_roots_of_trust(current, {other_subject}));
}

int main(int argc, char** argv)
{
  ccf::logger::config::default_init();
  ccf::crypto::openssl_sha256_init();
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  ccf::crypto::openssl_sha256_shutdown();
  if (context.shouldExit())
    return res;
  return res;
}