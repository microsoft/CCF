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
    auto format(const std::vector<uint8_t>& v, FormatContext& ctx)
    {
      return format_to(
        ctx.out(), "<vec[{}]: {:02x}>", v.size(), fmt::join(v, " "));
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
    auto format(const std::array<uint8_t, N>& a, FormatContext& ctx)
    {
      return format_to(ctx.out(), "<arr[{}]: {:02x}>", N, fmt::join(a, " "));
    }
  };
}
