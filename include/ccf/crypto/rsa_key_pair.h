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

namespace crypto
{
  class RSAKeyPair
  {
  public:
    static constexpr size_t default_public_key_size = 2048;
    static constexpr size_t default_public_exponent = 65537;

    RSAKeyPair() = default;
    RSAKeyPair(const RSAKeyPair&) = delete;
    RSAKeyPair(const Pem& pem);
    virtual ~RSAKeyPair() = default;

    virtual size_t key_size() const = 0;

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

    /**
     * Get the private key in PEM format
     */
    virtual Pem private_key_pem() const = 0;

    /**
     * Get the public key in PEM format
     */
    virtual Pem public_key_pem() const = 0;

    /**
     * Get the public key in DER format
     */
    virtual std::vector<uint8_t> public_key_der() const = 0;

    virtual std::vector<uint8_t> sign(
      std::span<const uint8_t> d, MDType md_type = MDType::NONE) const = 0;

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* signature,
      size_t signature_size,
      MDType md_type = MDType::NONE) = 0;

    virtual bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature,
      MDType md_type = MDType::NONE)
    {
      return verify(
        contents.data(),
        contents.size(),
        signature.data(),
        signature.size(),
        md_type);
    }

    virtual JsonWebKeyRSAPrivate private_key_jwk_rsa(
      const std::optional<std::string>& kid = std::nullopt) const = 0;
  };

  using RSAPublicKeyPtr = std::shared_ptr<RSAPublicKey>;
  using RSAKeyPairPtr = std::shared_ptr<RSAKeyPair>;

  RSAPublicKeyPtr make_rsa_public_key(const Pem& pem);
  RSAPublicKeyPtr make_rsa_public_key(const std::vector<uint8_t>& der);
  RSAPublicKeyPtr make_rsa_public_key(const JsonWebKeyRSAPublic& jwk);
  RSAPublicKeyPtr make_rsa_public_key(const uint8_t* data, size_t size);

  /**
   * Create a new public / private RSA key pair with specified size and exponent
   */
  RSAKeyPairPtr make_rsa_key_pair(
    size_t public_key_size = RSAKeyPair::default_public_key_size,
    size_t public_exponent = RSAKeyPair::default_public_exponent);

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
