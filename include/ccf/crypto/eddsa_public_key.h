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
  class EdDSAPublicKey
  {
  public:
    EdDSAPublicKey() = default;
    virtual ~EdDSAPublicKey() = default;

    /**
     * Construct from PEM
     */
    EdDSAPublicKey(const Pem& pem);

    virtual Pem public_key_pem() const = 0;

    /**
     * Verify that a signature was produced on contents with the private key
     * associated with the public key held by the object.
     *
     * @param contents Sequence of bytes that was signed
     * @param signature Signature as a sequence of bytes
     *
     * @return Whether the signature matches the contents and the key
     */
    virtual bool verify(
      const std::vector<uint8_t>& contents,
      const std::vector<uint8_t>& signature)
    {
      return verify(
        contents.data(), contents.size(), signature.data(), signature.size());
    }

    virtual bool verify(
      const uint8_t* contents,
      size_t contents_size,
      const uint8_t* signature,
      size_t signature_size) = 0;

    virtual CurveID get_curve_id() const = 0;

    virtual JsonWebKeyEdDSAPublic public_key_jwk_eddsa(
      const std::optional<std::string>& kid = std::nullopt) const = 0;
  };
}
