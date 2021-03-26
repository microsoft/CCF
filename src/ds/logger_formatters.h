// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <msgpack/msgpack.hpp>
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
      return format_to(ctx.out(), "{:02x}", fmt::join(p, ""));
    }
  };

  template <size_t N>
  struct formatter<std::array<uint8_t, N>>
  {
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
      return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const std::array<uint8_t, N>& p, FormatContext& ctx)
    {
      return format_to(ctx.out(), "{:02x}", fmt::join(p, ""));
    }
  };
}
