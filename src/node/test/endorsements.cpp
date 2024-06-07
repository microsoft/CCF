// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/pal/measurement.h"
#include "crypto/openssl/hash.h"
#include "ds/files.h"
#include "node/uvm_endorsements.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <cstdlib>
#include <doctest/doctest.h>

TEST_CASE("Check ECDSA Test endorsement")
{
  char* end_path = std::getenv("TEST_ENDORSEMENTS_PATH");
  REQUIRE(end_path != nullptr);

  auto endorsement = files::slurp(fmt::format("{}/ecdsa_test1.cose", end_path));
  REQUIRE(!endorsement.empty());

  std::string measurement =
    "5a84c66e9c8dd1a991e6d8b43a8aaae488940f87ce25ef6a62ad180cc3c73554ed7e4ccd10"
    "13456602758778d9d65c48";
  ccf::pal::PlatformAttestationMeasurement uvm_measurement;
  uvm_measurement.data = {measurement.begin(), measurement.end()};
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