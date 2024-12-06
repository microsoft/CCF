// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <fmt/format.h>

/**
 * Generic formatter for scoped enums.
 * Newer version of fmt does not include it by default.
 */
FMT_BEGIN_NAMESPACE
template <typename E>
struct formatter<E, std::enable_if_t<std::is_enum_v<E>, char>>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const E& value, FormatContext& ctx) const
  {
    return fmt::format_to(
      ctx.out(), "{}", static_cast<std::underlying_type_t<E>>(value));
  }
};
FMT_END_NAMESPACE

// ci-checks exception - defines a struct in the fmt namespace
namespace ccf
{}
