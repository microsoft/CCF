// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/verifier.h"

#include "crypto/openssl/verifier.h"

namespace crypto
{
  using VerifierPtr = std::shared_ptr<Verifier>;
  using VerifierUniquePtr = std::unique_ptr<Verifier>;

  VerifierUniquePtr make_unique_verifier(const std::vector<uint8_t>& cert)
  {
    return std::make_unique<Verifier_OpenSSL>(cert);
  }

  VerifierPtr make_verifier(const std::vector<uint8_t>& cert)
  {
    return std::make_shared<Verifier_OpenSSL>(cert);
  }

  VerifierUniquePtr make_unique_verifier(const Pem& pem)
  {
    return make_unique_verifier(pem.raw());
  }

  VerifierPtr make_verifier(const Pem& pem)
  {
    return make_verifier(pem.raw());
  }

  crypto::Pem cert_der_to_pem(const std::vector<uint8_t>& der)
  {
    return make_verifier(der)->cert_pem();
  }

  std::vector<uint8_t> cert_pem_to_der(const crypto::Pem& pem)
  {
    return make_verifier(pem)->cert_der();
  }

  std::vector<uint8_t> public_key_der_from_cert(const std::vector<uint8_t>& der)
  {
    return make_unique_verifier(der)->public_key_der();
  }

  crypto::Pem public_key_pem_from_cert(const std::vector<uint8_t>& der)
  {
    return make_unique_verifier(der)->public_key_pem();
  }

  std::string get_subject_name(const Pem& cert)
  {
    return make_verifier(cert)->subject();
  }
}
