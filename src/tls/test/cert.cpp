// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../../ds/cli_helper.h"
#include "crypto/key_pair.h"

#include <CLI11/CLI11.hpp>

int main(int argc, char** argv)
{
  CLI::App app{"Cert creation"};
  crypto::CertificateSubjectIdentity cert_subject_identity;
  app
    .add_option(
      "--sn",
      cert_subject_identity.name,
      "Subject Name in node certificate, eg. CN=CCF Node")
    ->capture_default_str();

  cli::add_subject_alternative_name_option(
    app,
    cert_subject_identity.sans,
    "--san",
    "Subject Alternative Name in node certificate. Can be either "
    "iPAddress:xxx.xxx.xxx.xxx, or dNSName:sub.domain.tld");
  CLI11_PARSE(app, argc, argv);

  auto kp = crypto::make_key_pair();
  auto icrt = kp->self_sign("CN=issuer");
  auto csr = kp->create_csr(cert_subject_identity.name);
  auto cert = kp->sign_csr(icrt, csr, cert_subject_identity.sans);

  std::cout << cert.str() << std::endl;
  return 0;
}