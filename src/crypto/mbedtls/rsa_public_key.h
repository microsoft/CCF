// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/rsa_public_key.h"
#include "mbedtls_wrappers.h"
#include "public_key.h"

#include <optional>
#include <string>
#include <vector>

namespace crypto
{
  class RSAPublicKey_mbedTLS : public PublicKey_mbedTLS, public RSAPublicKey
  {
  public:
    // Compatible with Azure HSM encryption schemes (see
    // https://docs.microsoft.com/en-gb/azure/key-vault/keys/about-keys#wrapkeyunwrapkey-encryptdecrypt)
    static constexpr auto rsa_padding_mode = MBEDTLS_RSA_PKCS_V21;
    static constexpr auto rsa_padding_digest_id = MBEDTLS_MD_SHA256;

    RSAPublicKey_mbedTLS() = default;
    virtual ~RSAPublicKey_mbedTLS() = default;

    RSAPublicKey_mbedTLS(mbedtls::PKContext&& c);
    RSAPublicKey_mbedTLS(const Pem& pem);
    RSAPublicKey_mbedTLS(const std::vector<uint8_t>& der);

    virtual size_t key_size() const override;

    virtual std::vector<uint8_t> rsa_oaep_wrap(
      const uint8_t* input,
      size_t input_size,
      const uint8_t* label = nullptr,
      size_t label_size = 0) override;

    virtual std::vector<uint8_t> rsa_oaep_wrap(
      const std::vector<uint8_t>& input,
      std::optional<std::vector<std::uint8_t>> label = std::nullopt) override;

    virtual Pem public_key_pem() const override;
    virtual std::vector<uint8_t> public_key_der() const override;

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* signature,
      size_t signature_size,
      MDType md_type = MDType::NONE) override;
  };
}
