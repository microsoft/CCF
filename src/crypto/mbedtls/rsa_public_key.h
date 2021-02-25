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

    RSAPublicKey_mbedTLS(crypto::mbedtls::PKContext&& c);
    RSAPublicKey_mbedTLS(const Pem& pem);
    RSAPublicKey_mbedTLS(const std::vector<uint8_t>& der);

    virtual size_t key_size() const;

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
