// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "openssl/crypto.h"
#include "ds/serialized.h"

#include "ccf/crypto/sha256.h"

namespace crypto
{
  constexpr size_t LIMBS = 10; // = ((256+80)/31)

  struct Share
  {
    uint32_t x;
    uint32_t y[LIMBS];

    bool operator==(const Share& other) const = default;

    ~Share() {
      OPENSSL_cleanse(y, sizeof(y));
    };

    HashBytes key() const
    {
      return sha256(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(y), sizeof(y)));
    }

    std::vector<uint8_t> serialise() const
    {
      auto size = sizeof(uint32_t) + sizeof(uint32_t) * LIMBS;
      std::vector<uint8_t> serialised(size);
      auto data = serialised.data();
      serialized::write(data, size, x);
      for (size_t i = 0; i < LIMBS; ++i)
      {
        serialized::write(data, size, y[i]);
      }
      return serialised;
    }
  };

  // supports any values for degree and shares, although usually 0 < degree <
  // share OUTPUT [output] an array of [shares] shares with distinct [x] OUTPUT
  // [raw_secret] to be SHA256-hashed to get uniformly-random bytes

  void sample_secret_and_shares(
    Share& raw_secret, const std::span<Share>& output, size_t degree);

  // input: an array of exactly (degree+1) shares
  // OUTPUT: raw_secret, to be SHA256-hashed to get uniformly-random bytes
  // throws when two shares have the same x coordinate
  void recover_secret(
    Share& raw_secret, const std::span<Share const>& input, size_t degree);
}