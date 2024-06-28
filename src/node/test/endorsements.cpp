// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

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
  auto endorsements =
    ccf::verify_uvm_endorsements(endorsement, uvm_measurement);
  REQUIRE(
    endorsements ==
    ccf::UVMEndorsements{
      "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3."
      "6.1.4.1.311.76.59.1.2",
      "ContainerPlat-AMD-UVM",
      "100"});
}

TEST_CASE("Check ECDSA Test endorsement")
{
  char* end_path = std::getenv("TEST_ENDORSEMENTS_PATH");
  REQUIRE(end_path != nullptr);

  auto endorsement = files::slurp(fmt::format("{}/ecdsa_test1.cose", end_path));
  REQUIRE(!endorsement.empty());

  ccf::pal::SnpAttestationMeasurement measurement(
    "5a84c66e9c8dd1a991e6d8b43a8aaae488940f87ce25ef6a62ad180cc3c73554ed7e4ccd10"
    "13456602758778d9d65c48");
  ccf::pal::PlatformAttestationMeasurement uvm_measurement(measurement);
  REQUIRE_THROWS_WITH_AS(
    ccf::verify_uvm_endorsements(endorsement, uvm_measurement),
    "UVM endorsements did "
    "did:x509:0:sha256:VFsRLNBh5Zy1HRtVl2IIXAl0lUs-xobEbskZ3XRDpCY::subject:CN:"
    "Test%20Leaf%20%28DO%20NOT%20TRUST%29, feed ConfAKS-AMD-UVM-Test, svn 0 do "
    "not match any of the known UVM roots of trust",
    std::logic_error);

  std::vector<ccf::UVMEndorsements> custom_roots_of_trust = {
    ccf::UVMEndorsements{
      "did:x509:0:sha256:VFsRLNBh5Zy1HRtVl2IIXAl0lUs-xobEbskZ3XRDpCY::subject:"
      "CN:Test%20Leaf%20%28DO%20NOT%20TRUST%29",
      "ConfAKS-AMD-UVM-Test",
      "0"}};

  auto endorsements = ccf::verify_uvm_endorsements(
    endorsement, uvm_measurement, custom_roots_of_trust);
  REQUIRE(endorsements == custom_roots_of_trust[0]);
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