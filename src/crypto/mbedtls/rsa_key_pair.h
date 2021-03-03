// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/rsa_key_pair.h"

#include "mbedtls_wrappers.h"
#include "rsa_public_key.h"

#include <optional>
#include <vector>

namespace crypto
{
  class RSAKeyPair_mbedTLS : public RSAPublicKey_mbedTLS, public RSAKeyPair
  {
  public:
    RSAKeyPair_mbedTLS(
      size_t public_key_size = default_public_key_size,
      size_t public_exponent = default_public_exponent);

    RSAKeyPair_mbedTLS(mbedtls::PKContext&& k);
    RSAKeyPair_mbedTLS(const RSAKeyPair&) = delete;
    RSAKeyPair_mbedTLS(const Pem& pem, CBuffer pw = nullb);

    virtual size_t key_size() const override;

    virtual ~RSAKeyPair_mbedTLS() = default;

    virtual std::vector<uint8_t> rsa_oaep_unwrap(
      const std::vector<uint8_t>& input,
      std::optional<std::vector<std::uint8_t>> label = std::nullopt) override;

    virtual Pem public_key_pem() const override;
  };
}
