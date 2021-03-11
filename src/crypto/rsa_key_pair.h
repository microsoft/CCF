// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "key_pair.h"
#include "pem.h"
#include "rsa_public_key.h"

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
    RSAKeyPair(const Pem& pem, CBuffer pw = nullb);
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
      std::optional<std::vector<std::uint8_t>> label = std::nullopt) = 0;

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
