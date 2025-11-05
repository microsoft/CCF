// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ccf/crypto/rsa_public_key.h"
#include "crypto/openssl/ec_public_key.h"
#include "crypto/openssl/hash.h"

#include <optional>
#include <string>
#include <vector>

namespace ccf::crypto
{
  class RSAPublicKey_OpenSSL : public RSAPublicKey
  {
  protected:
    EVP_PKEY* key{nullptr};

    // RSAKeyPair fully overwrites construction, so requires this to exist.
    RSAPublicKey_OpenSSL() = default;

  public:
    RSAPublicKey_OpenSSL(const Pem& pem);
    RSAPublicKey_OpenSSL(std::span<const uint8_t> der);
    RSAPublicKey_OpenSSL(const JsonWebKeyRSAPublic& jwk);

    RSAPublicKey_OpenSSL(EVP_PKEY* key);

    virtual ~RSAPublicKey_OpenSSL();

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

    virtual JsonWebKeyRSAPublic public_key_jwk(
      const std::optional<std::string>& kid = std::nullopt) const override;

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* signature,
      size_t signature_size,
      MDType md_type,
      RSAPadding padding,
      size_t salt_length) override;

    virtual bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* signature,
      size_t signature_size,
      MDType md_type,
      RSAPadding padding,
      size_t salt_length) override;

    OpenSSL::Unique_BIGNUM get_bn_param(const char* key_name) const;
  };

  std::vector<uint8_t> bn_to_bytes(const BIGNUM* bn);

  std::pair<std::vector<uint8_t>, std::vector<uint8_t>> rsa_public_raw_from_jwk(
    const JsonWebKeyRSAPublic& jwk);
}
