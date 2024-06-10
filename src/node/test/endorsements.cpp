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
  auto endorsements =
    ccf::verify_uvm_endorsements(endorsement, uvm_measurement);
}

int main(int argc, char** argv)
{
  logger::config::default_init();
  crypto::openssl_sha256_init();
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  crypto::openssl_sha256_shutdown();
  if (context.shouldExit())
    return res;
  return res;
}