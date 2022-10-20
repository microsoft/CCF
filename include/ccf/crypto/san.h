// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/ds/nonstd.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <string>

namespace crypto
{
  static const std::string IP_ADDRESS_PREFIX = "iPAddress:";
  static const std::string DNS_NAME_PREFIX = "dNSName:";

  struct SubjectAltName
  {
    std::string san;
    bool is_ip;

    bool operator==(const SubjectAltName& other) const = default;
    bool operator!=(const SubjectAltName& other) const = default;
  };
  DECLARE_JSON_TYPE(SubjectAltName);
  DECLARE_JSON_REQUIRED_FIELDS(SubjectAltName, san, is_ip);

  static SubjectAltName san_from_string(const std::string& str)
  {
    if (str.starts_with(IP_ADDRESS_PREFIX))
    {
      return {str.substr(IP_ADDRESS_PREFIX.size()), true};
    }
    else if (str.starts_with(DNS_NAME_PREFIX))
    {
      return {str.substr(DNS_NAME_PREFIX.size()), false};
    }
    else
    {
      throw std::logic_error(fmt::format(
        "SAN could not be parsed: {}, must be (iPAddress|dNSName):VALUE", str));
    }
  }

  static std::vector<SubjectAltName> sans_from_string_list(
    const std::vector<std::string>& list)
  {
    std::vector<SubjectAltName> sans = {};
    for (const auto& l : list)
    {
      sans.push_back(san_from_string(l));
    }
    return sans;
  }
}

FMT_BEGIN_NAMESPACE
template <>
struct formatter<crypto::SubjectAltName>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const crypto::SubjectAltName& san, FormatContext& ctx) const
    -> decltype(ctx.out())
  {
    std::string prefix;
    if (san.is_ip)
    {
      prefix = "IP";
    }
    else
    {
      prefix = "DNS";
    }
    return format_to(ctx.out(), "{}:{}", prefix, san.san);
  }
};
FMT_END_NAMESPACE