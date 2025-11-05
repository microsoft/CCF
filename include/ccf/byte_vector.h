// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/siphash.h"

#define FMT_HEADER_ONLY
#include <climits>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <small_vector/SmallVector.h>

namespace ccf
{
  using ByteVector = llvm_vecsmall::SmallVector<uint8_t, CHAR_BIT>;
}

// NOLINTBEGIN(cert-dcl58-cpp)
namespace std
{
  template <typename T, unsigned N>
  struct hash<llvm_vecsmall::SmallVector<T, N>>
  {
    size_t operator()(const llvm_vecsmall::SmallVector<T, N>& v) const
    {
      static constexpr ccf::siphash::SipKey k{
        0x7720796f726c694b, 0x2165726568207361};
      return ccf::siphash::siphash<2, 4>(v.data(), v.size(), k);
    }
  };
}
// NOLINTEND(cert-dcl58-cpp)

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
    // This is the same as std::isprint, but independent of the current locale.
    constexpr auto first_printable = 0x20;
    constexpr auto last_printable = 0x7e;
    auto printable = [](uint8_t b) { return b >= first_printable && b <= last_printable; };
    if (std::all_of(e.begin(), e.end(), printable))
    {
      return format_to(
        ctx.out(),
        "<uint8[{}]: ascii={}>",
        e.size(),
        std::string(e.begin(), e.end()));
    }
    return format_to(
      ctx.out(), "<uint8[{}]: hex={:02x}>", e.size(), fmt::join(e, " "));
  }
};
FMT_END_NAMESPACE
