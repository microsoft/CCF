// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/crypto/mldsa_key_pair.h"
#include "crypto/certs.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>

// Issues the ML-DSA certificates a CCF network presents to a TLS client: a
// self-signed service identity and a node certificate for 127.0.0.1 endorsed
// by it, with the node's private key.
//
// Usage: pqtest ML-DSA-44|ML-DSA-65|ML-DSA-87 <out-dir>

namespace
{
  const std::map<std::string, ccf::crypto::MLDSAParameterSet> PARAMETER_SETS = {
    {"ML-DSA-44", ccf::crypto::MLDSAParameterSet::ML_DSA_44},
    {"ML-DSA-65", ccf::crypto::MLDSAParameterSet::ML_DSA_65},
    {"ML-DSA-87", ccf::crypto::MLDSAParameterSet::ML_DSA_87}};

  void write_pem(const std::filesystem::path& path, const ccf::crypto::Pem& pem)
  {
    std::ofstream out(path);
    out << pem.str();
    if (!out)
    {
      throw std::runtime_error("Failed to write " + path.string());
    }
  }
}

int main(int argc, char** argv)
{
  if (argc != 3 || !PARAMETER_SETS.contains(argv[1]))
  {
    std::cerr << "Usage: pqtest ML-DSA-44|ML-DSA-65|ML-DSA-87 <out-dir>"
              << std::endl;
    return 1;
  }
  const auto parameter_set = PARAMETER_SETS.at(argv[1]);
  const std::filesystem::path out_dir = argv[2];

  const auto valid_from =
    ccf::ds::to_x509_time_string(std::chrono::system_clock::now());
  const auto valid_to =
    ccf::crypto::compute_cert_valid_to_string(valid_from, 365);

  const auto service_kp = ccf::crypto::make_mldsa_key_pair(parameter_set);
  const auto service_cert =
    service_kp->self_sign("CN=CCF Service", valid_from, valid_to);

  const auto node_kp = ccf::crypto::make_mldsa_key_pair(parameter_set);
  const auto node_cert = service_kp->sign_csr(
    service_cert,
    node_kp->create_csr("CN=CCF Node", {{"127.0.0.1", true}}),
    valid_from,
    valid_to);

  write_pem(out_dir / "service_cert.pem", service_cert);
  write_pem(out_dir / "node_cert.pem", node_cert);
  write_pem(out_dir / "node_privk.pem", node_kp->private_key_pem());
  return 0;
}
