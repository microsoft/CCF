// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

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
}
