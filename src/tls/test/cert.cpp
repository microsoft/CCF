// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../../ds/cli_helper.h"
#include "../key_pair.h"

#include <CLI11/CLI11.hpp>

int main(int argc, char** argv)
{
  CLI::App app{"Cert creation"};
  std::string subject_name;
  app
    .add_option(
      "--sn", subject_name, "Subject Name in node certificate, eg. CN=CCF Node")
    ->capture_default_str();

  std::vector<tls::SubjectAltName> subject_alternative_names;
  cli::add_subject_alternative_name_option(
    app,
    subject_alternative_names,
    "--san",
    "Subject Alternative Name in node certificate. Can be either "
    "iPAddress:xxx.xxx.xxx.xxx, or dNSName:sub.domain.tld");
  CLI11_PARSE(app, argc, argv);

  auto kp = tls::make_key_pair();
  auto icrt = kp->self_sign("CN=issuer");
  auto csr = kp->create_csr(subject_name);
  auto cert = kp->sign_csr(icrt, csr, subject_alternative_names);

  std::cout << cert.str() << std::endl;
  return 0;
}