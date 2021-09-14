// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/mbedtls/verifier.h"

#include "crypto/openssl/verifier.h"
#include "verifier.h"

namespace crypto
{
  using VerifierPtr = std::shared_ptr<Verifier>;
  using VerifierUniquePtr = std::unique_ptr<Verifier>;

  VerifierUniquePtr make_unique_verifier(const std::vector<uint8_t>& cert)
  {
#ifdef CRYPTO_PROVIDER_IS_MBEDTLS
    return std::make_unique<Verifier_mbedTLS>(cert);
#else
    return std::make_unique<Verifier_OpenSSL>(cert);
#endif
  }

  VerifierPtr make_verifier(const std::vector<uint8_t>& cert)
  {
#ifdef CRYPTO_PROVIDER_IS_MBEDTLS
    return std::make_shared<Verifier_mbedTLS>(cert);
#else
    return std::make_shared<Verifier_OpenSSL>(cert);
#endif
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

  void check_is_cert(const CBuffer& der)
  {
    make_unique_verifier((std::vector<uint8_t>)der); // throws on error
  }
}
