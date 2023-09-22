// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#define FMT_HEADER_ONLY
#include "ccf/crypto/hkdf.h"
#include "ccf/crypto/sha256.h"
#include "ds/serialized.h"
#include "openssl/crypto.h"

#include <fmt/format.h>

namespace crypto
{
  static constexpr size_t LIMBS = 10; // = ((256+80)/31)
  static constexpr const char* key_label = "CCF Wrapping Key v1";

  struct Share
  {
    // Index in a re-share, 0 is a full key, and 1+ is a partial share
    uint32_t x = 0;
    uint32_t y[LIMBS];
    constexpr static size_t serialised_size =
      sizeof(uint32_t) + sizeof(uint32_t) * LIMBS;

    Share() = default;
    bool operator==(const Share& other) const = default;

    ~Share()
    {
      OPENSSL_cleanse(y, sizeof(y));
    };

    HashBytes key(size_t key_size) const
    {
      if (x != 0)
      {
        throw std::invalid_argument("Cannot derive a key from a partial share");
      }
      const std::span<const uint8_t> ikm(
        reinterpret_cast<const uint8_t*>(y), sizeof(y));
      const std::span<const uint8_t> label(
        reinterpret_cast<const uint8_t*>(y), sizeof(y));
      auto k = crypto::hkdf(crypto::MDType::SHA256, key_size, ikm, {}, label);
      return k;
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
   * Enforces 1 < @p threshold <= number of shares.
   *
   * @param[out] raw_secret sampled secret value
   * @param[out] shares shares of raw_secret
   * @param threshold number of shares necessary to recover the secret
   *
   * Note that is it not safe to use the secret as a key directly,
   * and that a round of key derivation is necessary (Share::key()).
   */
  void sample_secret_and_shares(
    Share& raw_secret, const std::span<Share>& shares, size_t threshold);

  /** Using @p shares, recover @p secret, without authentication.
   *
   * @param[out] raw_secret recovered secret value
   * @param[in] shares shares of raw_secret
   * @param threshold number of shares necessary to recover the secret
   *
   * @throws std::invalid_argument if the number of shares is insufficient,
   * or if two shares have the same x coordinate.
   */
  void recover_unauthenticated_secret(
    Share& raw_secret, const std::span<Share const>& shares, size_t threshold);
}