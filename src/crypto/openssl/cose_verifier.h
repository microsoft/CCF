// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose_verifier.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/verifier.h"
#include "crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/public_key.h"

#include <chrono>
#include <openssl/x509.h>

namespace crypto
{
  class COSEVerifier_OpenSSL : public COSEVerifier
  {
  private:
    std::shared_ptr<PublicKey_OpenSSL> public_key;

  public:
    COSEVerifier_OpenSSL(const std::vector<uint8_t>& certificate);
    COSEVerifier_OpenSSL(const RSAPublicKeyPtr& pubk_ptr);
    virtual ~COSEVerifier_OpenSSL() override;
    virtual bool verify(
      const std::span<const uint8_t>& buf,
      std::span<uint8_t>& authned_content) const override;
  };
}
