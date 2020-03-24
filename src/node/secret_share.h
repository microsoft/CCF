// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tls/entropy.h"

#include <array>
#include <fmt/format_header_only.h>
#include <iostream>
#include <optional>
#include <vector>

extern "C"
{
#include "tls/random_bytes.h"

#include <sss/sss.h>
}

namespace ccf
{
  // The SecretSharing class provides static functions to split a secret into
  // shares and (re-)combine those shares into the original secret.
  // The size of the secret to share is fixed (SECRET_TO_SPLIT_LENGTH, 64
  // bytes). It is up to the caller to either shrink the secret if it is too
  // long. If the secret to split is shorter than SECRET_TO_SPLIT_LENGTH bytes,
  // the caller should ignore the extra bytes.
  class SecretSharing
  {
  public:
    static constexpr size_t SECRET_TO_SPLIT_LENGTH = sss_MLEN;
    static constexpr size_t SHARE_LENGTH = sss_SHARE_LEN;
    static constexpr size_t MAX_NUMBER_SHARES = 255; // As per sss documentation

    using Share = std::array<uint8_t, SHARE_LENGTH>;
    using SplitSecret = std::array<uint8_t, SECRET_TO_SPLIT_LENGTH>;

    static std::vector<Share> split(
      const SplitSecret& secret_to_split, size_t n, size_t k)
    {
      if (n == 0 || n > MAX_NUMBER_SHARES)
      {
        throw std::logic_error(
          fmt::format("n not in 1-{} range", MAX_NUMBER_SHARES));
      }

      if (k == 0 || k > n)
      {
        throw std::logic_error(fmt::format("k not in 1-n range (n: {})", n));
      }

      std::vector<Share> shares(n);

      sss_create_shares(
        reinterpret_cast<sss_Share*>(shares.data()),
        secret_to_split.data(),
        n,
        k);

      return shares;
    }

    static SplitSecret combine(const std::vector<Share>& shares, size_t k)
    {
      if (k == 0 || k > shares.size())
      {
        throw std::logic_error(
          fmt::format("k not in 1-n range (n: {})", shares.size()));
      }

      SplitSecret restored_secret;

      if (
        sss_combine_shares(
          restored_secret.data(), (sss_Share*)shares.data(), k) != 0)
      {
        throw std::logic_error(fmt::format(
          "Share combination failed: {} shares may be corrupted", k));
      }

      return restored_secret;
    }
  };
}