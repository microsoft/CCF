// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose_verifier.h"
#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/verifier.h"
#include "crypto/openssl/ec_public_key.h"
#include "crypto/openssl/public_key.h"
#include "crypto/openssl/rsa_public_key.h"

#include <chrono>
#include <openssl/x509.h>

namespace ccf::crypto
{
  class COSEVerifier_OpenSSL : public COSEVerifier
  {
  protected:
    std::shared_ptr<PublicKey_OpenSSL> public_key;

  public:
    ~COSEVerifier_OpenSSL() override;
    bool verify(
      const std::span<const uint8_t>& envelope,
      std::span<uint8_t>& authned_content) const override;
    [[nodiscard]] bool verify_detached(
      std::span<const uint8_t> envelope,
      std::span<const uint8_t> payload) const override;
  };

  class COSECertVerifier_OpenSSL : public COSEVerifier_OpenSSL
  {
  public:
    COSECertVerifier_OpenSSL(const std::vector<uint8_t>& certificate);
  };

  class COSEKeyVerifier_OpenSSL : public COSEVerifier_OpenSSL
  {
  public:
    COSEKeyVerifier_OpenSSL(const Pem& public_key);
    COSEKeyVerifier_OpenSSL(std::span<const uint8_t> public_key);
  };
}
