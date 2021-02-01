// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <msgpack/msgpack.hpp>
#include <sstream>

namespace fmt
{
  inline std::string uint8_vector_to_hex_string(const std::vector<uint8_t>& v)
  {
    std::stringstream ss;
    for (auto it = v.begin(); it != v.end(); it++)
    {
      ss << std::hex << static_cast<unsigned>(*it);
    }

    return ss.str();
  }

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
      return format_to(ctx.out(), uint8_vector_to_hex_string(p));
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
      return format_to(
        ctx.out(), uint8_vector_to_hex_string({p.begin(), p.end()}));
    }
  };
}
