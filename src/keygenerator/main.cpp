// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tls/keypair.h"

#include <CLI11/CLI11.hpp>
#include <fstream>
#include <string>

void gen_cert(const std::string& name)
{
  auto k = tls::make_key_pair();
  auto cert = k->self_sign("CN=" + name);
  auto privk = k->private_key_pem();

  std::ofstream(name + "_cert.pem", std::ios_base::trunc | std::ios::binary)
    .write((char*)cert.data(), cert.size());
  std::ofstream(name + "_privk.pem", std::ios_base::trunc | std::ios::binary)
    .write((char*)privk.data(), privk.size());
}

int main(int argc, char** argv)
{
  CLI::App app{"Key and Certificate Generator"};

  // Users/Members certificate generation
  std::string name;
  app.add_option("--name", name, "Key name", true)->required();

  CLI11_PARSE(app, argc, argv);

  gen_cert(name);

  return 0;
}
