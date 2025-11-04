// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/jwk.h"
#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/rsa_public_key.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ccf::crypto
{
  class RSAKeyPair : public RSAPublicKey
  {
  public:
    virtual Pem private_key_pem() const = 0;
    virtual std::vector<uint8_t> private_key_der() const = 0;
    virtual JsonWebKeyRSAPrivate private_key_jwk(
      const std::optional<std::string>& kid = std::nullopt) const = 0;

    virtual std::vector<uint8_t> sign(
      std::span<const uint8_t> d,
      MDType md_type = MDType::NONE,
      size_t salt_length = 0) const = 0;

    /**
     * Unwrap data using RSA-OAEP-256 (CKM_RSA_PKCS_OAEP)
     *
     * @param input Raw data to unwrap
     * @param label Optional string used as label during unwrapping
     *
     * @return Unwrapped data
     */
    virtual std::vector<uint8_t> rsa_oaep_unwrap(
      const std::vector<uint8_t>& input,
      const std::optional<std::vector<std::uint8_t>>& label = std::nullopt) = 0;
  };

  using RSAKeyPairPtr = std::shared_ptr<RSAKeyPair>;

  static constexpr size_t default_rsa_public_key_size = 2048;
  static constexpr size_t default_rsa_public_exponent = 65537;

  /**
   * Create a new public / private RSA key pair with specified size and exponent
   */
  RSAKeyPairPtr make_rsa_key_pair(
    size_t public_key_size = default_rsa_public_key_size,
    size_t public_exponent = default_rsa_public_exponent);

  /**
   * Create a public / private RSA key pair from existing private key data
   */
  RSAKeyPairPtr make_rsa_key_pair(const Pem& pem);

  /**
   * Create a public / private RSA key pair from existing JsonWebKeyRSAPrivate
   * object
   */
  RSAKeyPairPtr make_rsa_key_pair(const JsonWebKeyRSAPrivate& jwk);
}
