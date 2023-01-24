// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/jwk.h"
#include "ccf/crypto/pem.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace crypto
{
  class RSAPublicKey
  {
  public:
    RSAPublicKey() = default;
    virtual ~RSAPublicKey() = default;

    /**
     * Construct from PEM
     */
    RSAPublicKey(const Pem& pem);

    /**
     * Construct from DER
     */
    RSAPublicKey(const std::vector<uint8_t>& der);

    /**
     * Construct from JWK
     */
    RSAPublicKey(const JsonWebKeyRSAPublic& jwk);

    /**
     * Get the key size in bits
     */
    virtual size_t key_size() const = 0;

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
    virtual Pem public_key_pem() const = 0;

    /**
     * Get the public key in DER format
     */
    virtual std::vector<uint8_t> public_key_der() const = 0;

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* signature,
      size_t signature_size,
      MDType md_type = MDType::NONE) = 0;

    struct Components
    {
      std::vector<uint8_t> n;
      std::vector<uint8_t> e;
    };

    virtual Components components() const = 0;

    /**
     * Get the public key in JWK format
     */
    virtual JsonWebKeyRSAPublic public_key_jwk_rsa(
      const std::optional<std::string>& kid = std::nullopt) const = 0;
  };
}
