// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/rsa_key_pair.h"

#include "rsa_public_key.h"

#include <optional>
#include <vector>

namespace crypto
{
  class RSAKeyPair_OpenSSL : public RSAPublicKey_OpenSSL, public RSAKeyPair
  {
  public:
    RSAKeyPair_OpenSSL(
      size_t public_key_size = default_public_key_size,
      size_t public_exponent = default_public_exponent);
    RSAKeyPair_OpenSSL(EVP_PKEY* k);
    RSAKeyPair_OpenSSL(const RSAKeyPair&) = delete;
    RSAKeyPair_OpenSSL(const Pem& pem, CBuffer pw = nullb);
    virtual ~RSAKeyPair_OpenSSL() = default;

    virtual size_t key_size() const override;

    virtual std::vector<uint8_t> rsa_oaep_unwrap(
      const std::vector<uint8_t>& input,
      std::optional<std::vector<std::uint8_t>> label = std::nullopt) override;

    virtual Pem public_key_pem() const override;
    virtual std::vector<uint8_t> public_key_der() const override;
  };
}
