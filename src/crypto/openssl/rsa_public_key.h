// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/rsa_public_key.h"
#include "crypto/openssl/hash.h"
#include "crypto/openssl/public_key.h"

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
    RSAPublicKey_OpenSSL(const JsonWebKeyRSAPublic& jwk);
    virtual ~RSAPublicKey_OpenSSL() = default;

    virtual size_t key_size() const override;

    virtual std::vector<uint8_t> rsa_oaep_wrap(
      const uint8_t* input,
      size_t input_size,
      const uint8_t* label = nullptr,
      size_t label_size = 0) override;

    virtual std::vector<uint8_t> rsa_oaep_wrap(
      const std::vector<uint8_t>& input,
      const std::optional<std::vector<std::uint8_t>>& label =
        std::nullopt) override;

    virtual Pem public_key_pem() const override;
    virtual std::vector<uint8_t> public_key_der() const override;

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* signature,
      size_t signature_size,
      MDType md_type = MDType::NONE) override;

    virtual Components components() const override;

    static std::vector<uint8_t> bn_bytes(const BIGNUM* bn);

    virtual JsonWebKeyRSAPublic public_key_jwk_rsa(
      const std::optional<std::string>& kid = std::nullopt) const override;
  };
}
