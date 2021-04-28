// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/hex.h"
#include "kv/serialised_entry.h"

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

  template <>
  struct formatter<kv::serialisers::SerialisedEntry>
  {
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
      return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const kv::serialisers::SerialisedEntry& e, FormatContext& ctx)
    {
      if (std::find(e.begin(), e.end(), '\0') != e.end())
      {
        return format_to(
          ctx.out(), "<uint8[{}]: hex={:02x}>", e.size(), fmt::join(e, " "));
      }
      else
      {
        return format_to(
          ctx.out(),
          "<uint8[{}]: ascii={}>",
          e.size(),
          std::string(e.begin(), e.end()));
      }
    }
  };
}
