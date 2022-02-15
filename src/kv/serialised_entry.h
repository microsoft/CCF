// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ccf/byte_vector.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace kv::serialisers
{
  using SerialisedEntry = ccf::ByteVector;
}

namespace fmt
{
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
