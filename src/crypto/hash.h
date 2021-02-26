// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "mbedtls/hash.h"

#include "openssl/hash.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <ostream>

namespace crypto
{
  typedef MBedHashProvider HashProvider;
  typedef ISha256OpenSSL ISha256Hash;
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