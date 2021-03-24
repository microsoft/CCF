// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "hash_provider.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <ostream>

namespace crypto
{
  /** Compute the SHA256 hash of @p data
   * @param data The data to compute the hash of
   */
  std::vector<uint8_t> SHA256(const std::vector<uint8_t>& data);

  /** Create a default hash provider */
  std::shared_ptr<HashProvider> make_hash_provider();

  /** Create a default incremental SHA256 hash provider */
  std::shared_ptr<ISha256Hash> make_incremental_sha256();

  /** Perform HKDF key derivation */
  std::vector<uint8_t> hkdf(
    MDType md_type,
    size_t length,
    const std::vector<uint8_t>& ikm,
    const std::vector<uint8_t>& salt = {},
    const std::vector<uint8_t>& info = {});
}

namespace fmt
{
  template <>
  struct formatter<crypto::Sha256Hash>
  {
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
      return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const crypto::Sha256Hash& p, FormatContext& ctx)
    {
      return format_to(ctx.out(), "<sha256 {:02x}>", fmt::join(p.h, ""));
    }
  };
}