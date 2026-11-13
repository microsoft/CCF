// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

#include <cstdint>
#include <fmt/format.h>

namespace ccf
{
  /// Cryptographic family of an identity.
  // Preserve the existing 64-bit C++ representation.
  // NOLINTNEXTLINE(performance-enum-size)
  enum class IdentityType : uint64_t
  {
    /// Classical cryptographic identity.
    CLASSICAL = 0,
    /// Post-quantum cryptographic identity.
    PQ = 1,
  };

  DECLARE_JSON_ENUM(
    IdentityType,
    {{IdentityType::CLASSICAL, "CLASSICAL"}, {IdentityType::PQ, "PQ"}});
}

FMT_BEGIN_NAMESPACE

template <>
struct formatter<ccf::IdentityType>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const ccf::IdentityType& identity_type, FormatContext& ctx) const
    -> decltype(ctx.out())
  {
    switch (identity_type)
    {
      case ccf::IdentityType::CLASSICAL:
      {
        return format_to(ctx.out(), "CLASSICAL");
      }
      case ccf::IdentityType::PQ:
      {
        return format_to(ctx.out(), "PQ");
      }
    }
    return format_to(ctx.out(), "{}", static_cast<uint64_t>(identity_type));
  }
};

FMT_END_NAMESPACE
