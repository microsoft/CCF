// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/crypto/pem.h"

#include <chrono>
#include <doctest/doctest.h>
#include <string>

using namespace std;
using namespace ccf::crypto;

TEST_CASE("Invalid PEM errors do not disclose input")
{
  const std::string invalid_pem =
    "test-only-private-key-material\n-----END PRIVATE KEY-----";
  const auto* expected_error = "PEM constructed with non-PEM data";
  const auto* data = reinterpret_cast<const uint8_t*>(invalid_pem.data());

  REQUIRE_THROWS_WITH_AS(Pem{invalid_pem}, expected_error, std::runtime_error);
  REQUIRE_THROWS_WITH_AS(
    Pem(data, invalid_pem.size()), expected_error, std::runtime_error);
  REQUIRE_THROWS_WITH_AS(
    Pem(data, invalid_pem.size() + 1), expected_error, std::runtime_error);

  const std::vector<uint8_t> bytes(invalid_pem.begin(), invalid_pem.end());
  REQUIRE_THROWS_WITH_AS(Pem{bytes}, expected_error, std::runtime_error);
  REQUIRE_THROWS_WITH_AS(
    Pem{std::span<const uint8_t>(bytes)}, expected_error, std::runtime_error);
  REQUIRE_THROWS_WITH_AS(
    nlohmann::json(invalid_pem).get<Pem>(), expected_error, std::runtime_error);
  const nlohmann::json byte_array =
    nlohmann::json::array_t(bytes.begin(), bytes.end());
  REQUIRE_THROWS_WITH_AS(
    byte_array.get<Pem>(), expected_error, std::runtime_error);

  REQUIRE_THROWS_WITH_AS(
    Pem{std::string{}}, expected_error, std::runtime_error);
  REQUIRE_THROWS_WITH_AS(
    Pem(nullptr, 0), "Got PEM of size 0", std::logic_error);

  const nlohmann::json invalid_json_values[] = {
    {{"private_key", invalid_pem}}, nullptr, false, 42};
  for (const auto& j : invalid_json_values)
  {
    REQUIRE_THROWS_WITH_AS(
      j.get<Pem>(),
      "Unable to parse PEM: expected a string or array of bytes",
      std::runtime_error);
  }
}

TEST_CASE("PEM construction and JSON round trips")
{
  const std::string pem_string =
    "-----BEGIN PRIVATE KEY-----\ntest-only-placeholder\n"
    "-----END PRIVATE KEY-----";
  const Pem pem(pem_string);
  REQUIRE(pem.str() == pem_string);
  REQUIRE(Pem(pem.data(), pem.size()) == pem);
  REQUIRE(Pem(pem.data(), pem.size() + 1) == pem);
  REQUIRE(Pem(pem.raw()) == pem);
  REQUIRE(Pem(std::span<const uint8_t>(pem.data(), pem.size())) == pem);
  REQUIRE(nlohmann::json(pem).get<Pem>() == pem);
  const nlohmann::json byte_array =
    nlohmann::json::array_t(pem_string.begin(), pem_string.end());
  REQUIRE(byte_array.get<Pem>() == pem);
}

void check_bundles(
  const std::string& single_cert,
  const Pem& cert_pem,
  bool lr_before = false,
  bool lr_after = false)
{
  for (size_t count : {1, 2, 3, 10})
  {
    std::string certs;
    for (size_t i = 0; i < count; ++i)
    {
      if (lr_before)
      {
        certs += "\n";
      }
      certs += single_cert;
      if (lr_after)
      {
        certs += "\n";
      }
    }
    auto bundle = split_x509_cert_bundle(certs);
    REQUIRE(bundle.size() == count);
    for (const auto& pem : bundle)
    {
      REQUIRE(pem == cert_pem);
    }
  }
}

TEST_CASE("Split x509 cert bundle")
{
  REQUIRE(split_x509_cert_bundle("") == std::vector<Pem>{});

  const std::string single_cert =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIByDCCAU6gAwIBAgIQOBe5SrcwReWmSzTjzj2HDjAKBggqhkjOPQQDAzATMREw\n"
    "DwYDVQQDDAhDQ0YgTm9kZTAeFw0yMzA1MTcxMzUwMzFaFw0yMzA1MTgxMzUwMzBa\n"
    "MBMxETAPBgNVBAMMCENDRiBOb2RlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE74qL\n"
    "Ac/45tiriN5MuquYhHVdMGQRvYSm08HBfYcODtET88qC0A39o6Y2TmfbIn6BdjMG\n"
    "kD58o377ZMTaApQu/oJcwt7qZ9/LE8j8WU2qHn0cPTlpwH/2tiud2w+U3voSo2cw\n"
    "ZTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS9FJNwWSXtUpHaBV57EwTW\n"
    "oM8vHjAfBgNVHSMEGDAWgBS9FJNwWSXtUpHaBV57EwTWoM8vHjAPBgNVHREECDAG\n"
    "hwR/xF96MAoGCCqGSM49BAMDA2gAMGUCMQDKxpjPToJ7VSqKqQSeMuW9tr4iL+9I\n"
    "7gTGdGwiIYV1qTSS35Sk9XQZ0VpSa58c/5UCMEgmH71k7XlTGVUypm4jAgjpC46H\n"
    "s+hJpGMvyD9dKzEpZgmZYtghbyakUkwBiqmFQA==\n"
    "-----END CERTIFICATE-----";
  auto bundle = split_x509_cert_bundle(single_cert);
  const auto cert_pem = Pem(single_cert);

  check_bundles(single_cert, cert_pem);
  check_bundles(single_cert, cert_pem, true);
  check_bundles(single_cert, cert_pem, false, true);
  check_bundles(single_cert, cert_pem, true, true);

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
