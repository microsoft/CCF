// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/jwk.h"
#include "ccf/crypto/pem.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ccf::crypto
{
  enum class RSAPadding
  {
    PKCS1v15,
    PKCS_PSS,
  };

  class RSAPublicKey
  {
  public:
    /**
     * Get the key size in bits
     */
    [[nodiscard]] virtual size_t key_size() const = 0;

    /**
     * Wrap data using RSA-OAEP-256 (CKM_RSA_PKCS_OAEP)
     *
     * @param input Pointer to raw data to wrap
     * @param input_size Size of raw data
     * @param label Optional string used as label during wrapping
     * @param label_size Size of @p label
     *
     * @return Wrapped data
     */
    virtual std::vector<uint8_t> rsa_oaep_wrap(
      const uint8_t* input,
      size_t input_size,
      const uint8_t* label = nullptr,
      size_t label_size = 0) = 0;

    /**
     * Wrap data using RSA-OAEP-256 (CKM_RSA_PKCS_OAEP)
     *
     * @param input Raw data to wrap
     * @param label Optional string used as label during wrapping
     *
     * @return Wrapped data
     */
    virtual std::vector<uint8_t> rsa_oaep_wrap(
      const std::vector<uint8_t>& input,
      const std::optional<std::vector<std::uint8_t>>& label = std::nullopt) = 0;

    /**
     * Get the public key in PEM format
     */
    [[nodiscard]] virtual Pem public_key_pem() const = 0;

    /**
     * Get the public key in DER format
     */
    [[nodiscard]] virtual std::vector<uint8_t> public_key_der() const = 0;

    /**
     * Get the public key in JWK format
     */
    virtual JsonWebKeyRSAPublic public_key_jwk(
      const std::optional<std::string>& kid = std::nullopt) const = 0;

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* signature,
      size_t signature_size,
      MDType md_type,
      RSAPadding padding = RSAPadding::PKCS_PSS,
      size_t salt_length = 0) = 0;

    virtual bool verify_hash(
      const uint8_t* hash,
      size_t hash_size,
      const uint8_t* signature,
      size_t signature_size,
      MDType md_type,
      RSAPadding padding = RSAPadding::PKCS_PSS,
      size_t salt_length = 0) = 0;
  };

  using RSAPublicKeyPtr = std::shared_ptr<RSAPublicKey>;

  RSAPublicKeyPtr make_rsa_public_key(const uint8_t* data, size_t size);

  RSAPublicKeyPtr make_rsa_public_key(const Pem& public_pem);

  RSAPublicKeyPtr make_rsa_public_key(const std::vector<uint8_t>& der);

  RSAPublicKeyPtr make_rsa_public_key(const JsonWebKeyRSAPublic& jwk);
}
