// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <mbedtls/asn1.h>
#include <mbedtls/oid.h>

namespace fmt
{
  template <>
  struct formatter<mbedtls_asn1_named_data>
  {
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
      return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const mbedtls_asn1_named_data& n, FormatContext& ctx)
    {
      const mbedtls_asn1_named_data* current = &n;

      format_to(ctx.out(), "[");

      while (current != nullptr)
      {
        const auto oid = current->oid;
        const char* oid_name;
        mbedtls_oid_get_attr_short_name(&oid, &oid_name);

        const auto val = current->val;

        format_to(
          ctx.out(),
          "{}{}={}",
          (current == &n ? "" : ", "),
          oid_name,
          std::string_view((char const*)val.p, val.len));

        current = current->next;
      }

      return format_to(ctx.out(), "]");
    }
  };
}