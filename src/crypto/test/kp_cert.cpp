// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/crypto/ec_key_pair.h"
#include "crypto/certs.h"
#include "ds/cli_helper.h"

#include <CLI11/CLI11.hpp>

constexpr size_t certificate_validity_period_days = 365;
auto valid_from =
  ccf::ds::to_x509_time_string(std::chrono::system_clock::now());
auto valid_to = ccf::crypto::compute_cert_valid_to_string(
  valid_from, certificate_validity_period_days);

int main(int argc, char** argv)
{
  CLI::App app{"Cert creation"};
  std::string name;
  app
    .add_option(
      "--sn", name, "Subject Name in node certificate, eg. CN=CCF Node")
    ->capture_default_str();

  std::vector<ccf::crypto::SubjectAltName> sans = {};
  cli::add_subject_alternative_name_option(
    app,
    sans,
    "--san",
    "Subject Alternative Name in node certificate. Can be either "
    "iPAddress:xxx.xxx.xxx.xxx, or dNSName:sub.domain.tld");
  CLI11_PARSE(app, argc, argv);

  auto kp = ccf::crypto::make_ec_key_pair();
  auto icrt = kp->self_sign("CN=issuer", valid_from, valid_to);
  auto csr = kp->create_csr(name, sans);
  auto cert = kp->sign_csr(icrt, csr, valid_from, valid_to);

  std::cout << cert.str() << std::endl;
  return 0;
}
