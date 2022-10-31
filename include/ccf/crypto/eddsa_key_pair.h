// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/curve.h"
#include "ccf/crypto/eddsa_key_pair.h"
#include "ccf/crypto/eddsa_public_key.h"
#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/public_key.h"
#include "ccf/crypto/san.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace crypto
{
  class EdDSAKeyPair
  {
  public:
    virtual ~EdDSAKeyPair() = default;

    /**
     * Get the private key in PEM format
     */
    virtual Pem private_key_pem() const = 0;

    /**
     * Get the public key in PEM format
     */
    virtual Pem public_key_pem() const = 0;

    virtual std::vector<uint8_t> sign(std::span<const uint8_t> d) const = 0;

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* signature,
      size_t signature_size) = 0;

    virtual bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature)
    {
      return verify(
        contents.data(), contents.size(), signature.data(), signature.size());
    }
  };

  using EdDSAPublicKeyPtr = std::shared_ptr<EdDSAPublicKey>;
  using EdDSAKeyPairPtr = std::shared_ptr<EdDSAKeyPair>;

  /**
   * Create a new public / private EdDSA key pair on specified curve and
   * implementation
   *
   * @param curve_id Elliptic curve to use
   * @return Key pair
   */
  EdDSAKeyPairPtr make_eddsa_key_pair(CurveID curve_id);

  /**
   * Create a public / private RSA key pair from existing private key data
   */
  EdDSAPublicKeyPtr make_eddsa_public_key(const Pem& pem);
}
