// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/rsa_public_key.h"
#include "crypto/openssl/rsa_public_key.h"

#include <optional>
#include <string>
#include <vector>

namespace ccf::crypto
{
  class RSAKeyPair_OpenSSL : public RSAPublicKey_OpenSSL, public RSAKeyPair
  {
  public:
    RSAKeyPair_OpenSSL(size_t public_key_size, size_t public_exponent);
    RSAKeyPair_OpenSSL(const Pem& pem);
    RSAKeyPair_OpenSSL(const JsonWebKeyRSAPrivate& jwk);
    virtual ~RSAKeyPair_OpenSSL() = default;

    RSAKeyPair_OpenSSL(EVP_PKEY* k);

    virtual Pem private_key_pem() const override;
    virtual std::vector<uint8_t> private_key_der() const override;
    virtual JsonWebKeyRSAPrivate private_key_jwk(
      const std::optional<std::string>& kid = std::nullopt) const override;

    virtual std::vector<uint8_t> sign(
      std::span<const uint8_t> d,
      MDType md_type = MDType::NONE,
      size_t salt_length = 0) const override;

    virtual std::vector<uint8_t> rsa_oaep_unwrap(
      const std::vector<uint8_t>& input,
      const std::optional<std::vector<std::uint8_t>>& label =
        std::nullopt) override;

    virtual size_t key_size() const override
    {
      return RSAPublicKey_OpenSSL::key_size();
    }

    virtual std::vector<uint8_t> rsa_oaep_wrap(
      const uint8_t* input,
      size_t input_size,
      const uint8_t* label = nullptr,
      size_t label_size = 0) override
    {
      return RSAPublicKey_OpenSSL::rsa_oaep_wrap(
        input, input_size, label, label_size);
    }

    virtual std::vector<uint8_t> rsa_oaep_wrap(
      const std::vector<uint8_t>& input,
      const std::optional<std::vector<std::uint8_t>>& label =
        std::nullopt) override
    {
      return RSAPublicKey_OpenSSL::rsa_oaep_wrap(input, label);
    }

    virtual Pem public_key_pem() const override
    {
      return RSAPublicKey_OpenSSL::public_key_pem();
    }
    virtual std::vector<uint8_t> public_key_der() const override
    {
      return RSAPublicKey_OpenSSL::public_key_der();
    }

    virtual JsonWebKeyRSAPublic public_key_jwk(
      const std::optional<std::string>& kid = std::nullopt) const override
    {
      return RSAPublicKey_OpenSSL::public_key_jwk(kid);
    }

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* signature,
      size_t signature_size,
      MDType md_type,
      RSAPadding padding,
      size_t salt_length) override
    {
      return RSAPublicKey_OpenSSL::verify(
        contents,
        contents_size,
        signature,
        signature_size,
        md_type,
        padding,
        salt_length);
    }

    virtual bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* signature,
      size_t signature_size,
      MDType md_type,
      RSAPadding padding,
      size_t salt_length) override
    {
      return RSAPublicKey_OpenSSL::verify_hash(
        hash,
        hash_size,
        signature,
        signature_size,
        md_type,
        padding,
        salt_length);
    }
  };
}
