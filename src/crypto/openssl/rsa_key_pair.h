// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/rsa_public_key.h"
#include "crypto/openssl/rsa_public_key.h"

#include <optional>
#include <string>
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
    RSAKeyPair_OpenSSL(const Pem& pem);
    virtual ~RSAKeyPair_OpenSSL() = default;

    virtual size_t key_size() const override;

    virtual std::vector<uint8_t> rsa_oaep_unwrap(
      const std::vector<uint8_t>& input,
      const std::optional<std::vector<std::uint8_t>>& label =
        std::nullopt) override;

    virtual Pem private_key_pem() const override;
    virtual Pem public_key_pem() const override;
    virtual std::vector<uint8_t> public_key_der() const override;

    virtual std::vector<uint8_t> sign(
      std::span<const uint8_t> d, MDType md_type = MDType::NONE) const override;

    static std::vector<uint8_t> sign(
      const std::vector<uint8_t>& data,
      const Pem& private_key,
      MDType md_type = MDType::NONE);

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* signature,
      size_t signature_size,
      MDType md_type = MDType::NONE) override;

    virtual JsonWebKeyRSAPrivate private_key_jwk_rsa(
      const std::optional<std::string>& kid = std::nullopt) const override;
  };
}
