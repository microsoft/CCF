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
#include "tls/randombytes.h"

#include <sss/sss.h>
}

namespace ccf
{
  class KeySharing
  {
    // Notes: it is up to the caller to pad the data to split TODO: Elaborate
  public:
    static constexpr size_t DATA_LENGTH = sss_MLEN;
    static constexpr size_t SHARE_LENGTH = sss_SHARE_LEN;
    static constexpr size_t MAX_NUMBER_SHARE = 255; // As per sss documentation

    using Share = std::array<uint8_t, SHARE_LENGTH>;
    using Data = std::array<uint8_t, DATA_LENGTH>;

  private:
    std::vector<Share> shares;

  public:
    KeySharing(size_t n) : shares(n)
    {
      if (n == 0 || n > MAX_NUMBER_SHARE)
      {
        throw std::logic_error(
          fmt::format("n not in 1-{} range", MAX_NUMBER_SHARE));
      }
    }

    std::vector<Share> split(const Data& data, size_t k)
    {
      if (k == 0 || k > shares.size())
      {
        throw std::logic_error(
          fmt::format("k not in 1-n range (n: {})", shares.size()));
      }

      sss_create_shares(
        (sss_Share*)shares.data(), data.data(), shares.size(), k);

      return shares;
    }

    // TODO: Should this be static or something? No need for context here!
    Data combine(const std::vector<Share>& shares_, size_t k)
    {
      Data restored;

      if (k == 0 || k > shares_.size())
      {
        throw std::logic_error(
          fmt::format("k not in 1-n range (n: {})", shares_.size()));
      }

      if (
        sss_combine_shares(restored.data(), (sss_Share*)shares_.data(), k) != 0)
      {
        throw std::logic_error(fmt::format(
          "Share combination failed: {} shares may be corrupted", k));
      }

      return restored;
    }
  };
}