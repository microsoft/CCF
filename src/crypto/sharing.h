// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#define FMT_HEADER_ONLY
#include "ccf/crypto/sha256.h"
#include "ds/serialized.h"
#include "openssl/crypto.h"

#include <fmt/format.h>

namespace crypto
{
  constexpr size_t LIMBS = 10; // = ((256+80)/31)

  struct Share
  {
    uint32_t x;
    uint32_t y[LIMBS];

    Share() = default;
    bool operator==(const Share& other) const = default;

    ~Share()
    {
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

    Share(const std::span<uint8_t const>& serialised)
    {
      if (serialised.size() != sizeof(uint32_t) + sizeof(uint32_t) * LIMBS)
      {
        throw std::invalid_argument("Invalid serialised share size");
      }
      auto data = serialised.data();
      auto size = serialised.size();
      x = serialized::read<uint32_t>(data, size);
      for (size_t i = 0; i < LIMBS; ++i)
      {
        y[i] = serialized::read<uint32_t>(data, size);
      }
    }

    std::string to_str() const
    {
      return fmt::format("x: {} y: {}", x, fmt::join(y, ", "));
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