// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/crypto/pem.h"

#include <chrono>
#include <doctest/doctest.h>
#include <string>

using namespace std;
using namespace ccf::crypto;

TEST_CASE("Split x509 cert bundle")
{
  REQUIRE(split_x509_cert_bundle("") == std::vector<Pem>{});

  const std::string single_cert =
    "-----BEGIN "
    "CERTIFICATE-----"
    "\nMIIByDCCAU6gAwIBAgIQOBe5SrcwReWmSzTjzj2HDjAKBggqhkjOPQQDAzATMREw\nDwYDVQ"
    "QDDAhDQ0YgTm9kZTAeFw0yMzA1MTcxMzUwMzFaFw0yMzA1MTgxMzUwMzBa\nMBMxETAPBgNVBA"
    "MMCENDRiBOb2RlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE74qL\nAc/"
    "45tiriN5MuquYhHVdMGQRvYSm08HBfYcODtET88qC0A39o6Y2TmfbIn6BdjMG\nkD58o377ZMT"
    "aApQu/oJcwt7qZ9/LE8j8WU2qHn0cPTlpwH/"
    "2tiud2w+U3voSo2cw\nZTASBgNVHRMBAf8ECDAGAQH/"
    "AgEAMB0GA1UdDgQWBBS9FJNwWSXtUpHaBV57EwTW\noM8vHjAfBgNVHSMEGDAWgBS9FJNwWSXt"
    "UpHaBV57EwTWoM8vHjAPBgNVHREECDAG\nhwR/"
    "xF96MAoGCCqGSM49BAMDA2gAMGUCMQDKxpjPToJ7VSqKqQSeMuW9tr4iL+"
    "9I\n7gTGdGwiIYV1qTSS35Sk9XQZ0VpSa58c/"
    "5UCMEgmH71k7XlTGVUypm4jAgjpC46H\ns+hJpGMvyD9dKzEpZgmZYtghbyakUkwBiqmFQA=="
    "\n-----END CERTIFICATE-----";
  auto bundle = split_x509_cert_bundle(single_cert);
  const auto cert_pem = Pem(single_cert);
  REQUIRE(bundle.size() == 1);
  REQUIRE(bundle[0] == cert_pem);

  const std::string two_certs = single_cert + single_cert;
  bundle = split_x509_cert_bundle(two_certs);
  REQUIRE(bundle.size() == 2);
  REQUIRE(bundle[0] == cert_pem);
  REQUIRE(bundle[1] == cert_pem);

  std::string bundle_with_invalid_suffix = single_cert + "ignored suffix";
  bundle = split_x509_cert_bundle(bundle_with_invalid_suffix);
  REQUIRE(bundle.size() == 1);
  REQUIRE(bundle[0] == cert_pem);

  bundle_with_invalid_suffix =
    single_cert + "-----BEGIN CERTIFICATE-----\nignored suffix";
  bundle = split_x509_cert_bundle(bundle_with_invalid_suffix);
  REQUIRE(bundle.size() == 1);
  REQUIRE(bundle[0] == cert_pem);

  const std::string bundle_with_very_invalid_pem =
    single_cert + "not a cert\n-----END CERTIFICATE-----";
  REQUIRE_THROWS_AS(
    split_x509_cert_bundle(bundle_with_very_invalid_pem), std::runtime_error);
}
