// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/files.h"
#include "tls/base64.h"

#include <CLI11/CLI11.hpp>
#include <vector>

int main(int argc, char** argv)
{
  CLI::App app{"recovery share enc"};

  std::string member_privk_file;
  app.add_option(
    "--member-enc-privk-file",
    member_privk_file,
    "Member encryption private key file");

  std::string network_pubk_file;
  app.add_option(
    "--network-enc-pubk-file",
    network_pubk_file,
    "Previous network encryption public key file");

  std::string recovery_share;
  app.add_option(
    "--recovery_share", recovery_share, "Encrypted recovery share (base64)");

  std::string nonce;
  app.add_option("--nonce", nonce, "Nonce (base64)");

  CLI11_PARSE(app, argc, argv);

  // TODO:
  // 1. Build and install this in cmake
  // 2. Crypto box open
  // 3. Output base 64 encoded recovery share

  auto raw_recovery_share = tls::raw_from_b64(recovery_share);
  auto raw_nonce = tls::raw_from_b64(nonce);


}