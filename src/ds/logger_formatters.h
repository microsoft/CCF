// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/hex.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <sstream>

namespace fmt
{
  template <>
  struct formatter<std::vector<uint8_t>>
  {
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
      return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const std::vector<uint8_t>& p, FormatContext& ctx)
    {
      return format_to(ctx.out(), ds::to_hex(p));
    }
  };

  template <>
  struct formatter<std::array<uint8_t, 32>>
  {
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
      return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const std::array<uint8_t, 32>& p, FormatContext& ctx)
    {
      return format_to(ctx.out(), ds::to_hex(p));
    }
  };
}
