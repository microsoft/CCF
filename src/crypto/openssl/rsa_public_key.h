// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/rsa_public_key.h"

#include "key_pair.h"

#include <optional>
#include <string>
#include <vector>

namespace crypto
{
  class RSAPublicKey_OpenSSL : public PublicKey_OpenSSL, public RSAPublicKey
  {
  public:
    RSAPublicKey_OpenSSL() = default;
    RSAPublicKey_OpenSSL(EVP_PKEY* c);
    RSAPublicKey_OpenSSL(const Pem& pem);
    RSAPublicKey_OpenSSL(const std::vector<uint8_t>& der);
    virtual ~RSAPublicKey_OpenSSL() = default;

    virtual std::vector<uint8_t> wrap(
      const uint8_t* input,
      size_t input_size,
      const uint8_t* label = nullptr,
      size_t label_size = 0);

    virtual std::vector<uint8_t> wrap(
      const std::vector<uint8_t>& input,
      std::optional<std::string> label = std::nullopt);

    virtual Pem public_key_pem() const;
  };
}
