// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/crypto/pem.h"

#include "ccf/crypto/verifier.h"
#include "ccf/pal/attestation_sev_snp.h"

#include <chrono>
#include <doctest/doctest.h>
#include <string>

using namespace std;
using namespace ccf::crypto;

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

TEST_CASE("foo")
{
  Pem chip_certificate(
    "-----BEGIN CERTIFICATE-----\n"
    "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\n"
    "e0Ds/zuYFw==\n"
    "-----END CERTIFICATE-----");

  Pem sev_version_certificate(
    "-----BEGIN CERTIFICATE-----\n"
    "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\n"
    "-----END CERTIFICATE-----");

  Pem root_certificate(
    "-----BEGIN CERTIFICATE-----\n"
    "MIIGYzCCBBKgAwIBAgIDAQAAMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAIC\n"
    "BQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDAS\n"
    "BgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEg\n"
    "Q2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZp\n"
    "Y2VzMRIwEAYDVQQDDAlBUkstTWlsYW4wHhcNMjAxMDIyMTcyMzA1WhcNNDUxMDIy\n"
    "MTcyMzA1WjB7MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDAS\n"
    "BgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5j\n"
    "ZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJQVJLLU1pbGFuMIICIjANBgkqhkiG\n"
    "9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsVmD7FktuotWwX1fNg\n"
    "W41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU0V5tkKiU1EesNFta\n"
    "1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S1ju8X93+6dxDUrG2\n"
    "SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI52Naz5m2B+O+vjsC0\n"
    "60d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3KFYXP59XmJgtcog05\n"
    "gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd/y8KxX7jksTEzAOg\n"
    "bKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBkgnlENEWx1UcbQQrs\n"
    "+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V9TJQqnN3Q53kt5vi\n"
    "Qi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnqz55I0u33wh4r0ZNQ\n"
    "eTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+OgpCCoMNit2uLo9M18\n"
    "fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXoQPHfbkH0CyPfhl1j\n"
    "WhJFZasCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSFrBrRQ/fI\n"
    "rFXUxR1BSKvVeErUUzAPBgNVHRMBAf8EBTADAQH/MDoGA1UdHwQzMDEwL6AtoCuG\n"
    "KWh0dHBzOi8va2RzaW50Zi5hbWQuY29tL3ZjZWsvdjEvTWlsYW4vY3JsMEYGCSqG\n"
    "SIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZI\n"
    "AWUDBAICBQCiAwIBMKMDAgEBA4ICAQC6m0kDp6zv4Ojfgy+zleehsx6ol0ocgVel\n"
    "ETobpx+EuCsqVFRPK1jZ1sp/lyd9+0fQ0r66n7kagRk4Ca39g66WGTJMeJdqYriw\n"
    "STjjDCKVPSesWXYPVAyDhmP5n2v+BYipZWhpvqpaiO+EGK5IBP+578QeW/sSokrK\n"
    "dHaLAxG2LhZxj9aF73fqC7OAJZ5aPonw4RE299FVarh1Tx2eT3wSgkDgutCTB1Yq\n"
    "zT5DuwvAe+co2CIVIzMDamYuSFjPN0BCgojl7V+bTou7dMsqIu/TW/rPCX9/EUcp\n"
    "KGKqPQ3P+N9r1hjEFY1plBg93t53OOo49GNI+V1zvXPLI6xIFVsh+mto2RtgEX/e\n"
    "pmMKTNN6psW88qg7c1hTWtN6MbRuQ0vm+O+/2tKBF2h8THb94OvvHHoFDpbCELlq\n"
    "HnIYhxy0YKXGyaW1NjfULxrrmxVW4wcn5E8GddmvNa6yYm8scJagEi13mhGu4Jqh\n"
    "3QU3sf8iUSUr09xQDwHtOQUVIqx4maBZPBtSMf+qUDtjXSSq8lfWcd8bLr9mdsUn\n"
    "JZJ0+tuPMKmBnSH860llKk+VpVQsgqbzDIvOLvD6W1Umq25boxCYJ+TuBoa4s+HH\n"
    "CViAvgT9kf/rBq1d+ivj6skkHxuzcxbk1xv6ZGxrteJxVH7KlX7YRdZ6eARKwLe4\n"
    "AFZEAwoKCQ==\n"
    "-----END CERTIFICATE-----");

  auto root_cert_verifier = ccf::crypto::make_verifier(root_certificate);

  if (
    root_cert_verifier->public_key_pem().str() !=
    ccf::pal::snp::amd_milan_root_signing_public_key)
  {
    throw std::logic_error(fmt::format(
      "SEV-SNP: The root of trust public key for this attestation was not "
      "the expected one {}",
      root_cert_verifier->public_key_pem().str()));
  }

  if (!root_cert_verifier->verify_certificate({&root_certificate}))
  {
    throw std::logic_error(
      "SEV-SNP: The root of trust public key for this attestation was not "
      "self signed as expected");
  }

  auto chip_cert_verifier = ccf::crypto::make_verifier(chip_certificate);
  if (!chip_cert_verifier->verify_certificate(
        {&root_certificate, &sev_version_certificate}))
  {
    throw std::logic_error(
      "SEV-SNP: The chain of signatures from the root of trust to this "
      "attestation is broken");
  }
}
