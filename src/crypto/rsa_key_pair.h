// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "key_pair.h"
#include "pem.h"

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
     * Wrap data using RSA-OAEP-256
     *
     * @param input Pointer to raw data to wrap
     * @param input_size Size of raw data
     * @param label Optional string used as label during wrapping
     * @param label Optional string used as label during wrapping
     *
     * @return Wrapped data
     */
    virtual std::vector<uint8_t> wrap(
      const uint8_t* input,
      size_t input_size,
      const uint8_t* label = nullptr,
      size_t label_size = 0) = 0;

    /**
     * Wrap data using RSA-OAEP-256
     *
     * @param input Raw data to wrap
     * @param label Optional string used as label during wrapping
     *
     * @return Wrapped data
     */
    virtual std::vector<uint8_t> wrap(
      const std::vector<uint8_t>& input,
      std::optional<std::string> label = std::nullopt) = 0;

    /**
     * Get the public key in PEM format
     */
    virtual Pem public_key_pem() const = 0;
  };

  class RSAKeyPair
  {
  public:
    static constexpr size_t default_public_key_size = 2048;
    static constexpr size_t default_public_exponent = 65537;

    RSAKeyPair() = default;
    RSAKeyPair(const RSAKeyPair&) = delete;
    RSAKeyPair(const Pem& pem, CBuffer pw = nullb);
    virtual ~RSAKeyPair() = default;

    /**
     * Unwrap data using RSA-OAEP-256
     *
     * @param input Raw data to unwrap
     * @param label Optional string used as label during unwrapping
     *
     * @return Unwrapped data
     */
    virtual std::vector<uint8_t> unwrap(
      const std::vector<uint8_t>& input,
      std::optional<std::string> label = std::nullopt) = 0;

    /**
     * Get the public key in PEM format
     */
    virtual Pem public_key_pem() const = 0;
  };

  using RSAPublicKeyPtr = std::shared_ptr<RSAPublicKey>;
  using RSAKeyPairPtr = std::shared_ptr<RSAKeyPair>;

  RSAPublicKeyPtr make_rsa_public_key(const Pem& pem);
  RSAPublicKeyPtr make_rsa_public_key(const std::vector<uint8_t>& der);
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
  RSAKeyPairPtr make_rsa_key_pair(const Pem& pem, CBuffer pw = nullb);
}
