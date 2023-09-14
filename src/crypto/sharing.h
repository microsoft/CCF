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
    constexpr static size_t serialised_size =
      sizeof(uint32_t) + sizeof(uint32_t) * LIMBS;

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
      auto size = serialised_size;
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
      if (serialised.size() != serialised_size)
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

  /** Sample a secret into @p raw_secret, and split it into @p output.
   * Supports any values for degree and shares, although usually
   * 0 < @p degree < number of shares.
   * @param[out] raw_secret sampled secret value
   * @param[out] shares shares of raw_secret
   * @param degree degree of the polynomial used to generate shares
   *
   * Note that for a secret sampled with @p degree, degree + 1 shares
   * are required to recover the secret.
   */
  void sample_secret_and_shares(
    Share& raw_secret, const std::span<Share>& shares, size_t degree);

  /** Using @p shares, recover @p secret.
   * @param[out] raw_secret recovered secret value
   * @param[in] shares shares of raw_secret
   * @param degree degree of the polynomial used to generate shares
   *
   * Note that for a secret sampled with @p degree, degree + 1 shares
   * are required to recover the secret.
   *
   * @throws std::invalid_argument if the number of shares is insufficient,
   * or if two shares have the same x coordinate.
   */
  void recover_secret(
    Share& raw_secret, const std::span<Share const>& shares, size_t degree);
}