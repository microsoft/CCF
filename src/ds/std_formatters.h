// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/hex.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <sstream>

/// Defines fmt::formatter instantiations for commonly used std:: container
/// types

FMT_BEGIN_NAMESPACE
template <>
struct formatter<std::vector<uint8_t>>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const std::vector<uint8_t>& v, FormatContext& ctx) const
  {
    return fmt::format_to(
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
  auto format(const std::array<uint8_t, N>& a, FormatContext& ctx) const
  {
    return fmt::format_to(ctx.out(), "<arr[{}]: {:02x}>", N, fmt::join(a, " "));
  }
};
FMT_END_NAMESPACE
