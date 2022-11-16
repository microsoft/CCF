// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/siphash.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <small_vector/SmallVector.h>

namespace ccf
{
  using ByteVector = llvm_vecsmall::SmallVector<uint8_t, 8>;
}

namespace std
{
  template <typename T, unsigned N>
  struct hash<llvm_vecsmall::SmallVector<T, N>>
  {
    size_t operator()(const llvm_vecsmall::SmallVector<T, N>& v) const
    {
      static constexpr siphash::SipKey k{
        0x7720796f726c694b, 0x2165726568207361};
      return siphash::siphash<2, 4>(v.data(), v.size(), k);
    }
  };
}

FMT_BEGIN_NAMESPACE
template <>
struct formatter<ccf::ByteVector>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const ccf::ByteVector& e, FormatContext& ctx) const
  {
    auto non_printable = [](uint8_t b) { return b < 0x20 || b > 0x7e; };
    if (std::find_if(e.begin(), e.end(), non_printable) != e.end())
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
FMT_END_NAMESPACE
