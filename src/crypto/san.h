// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <string>

namespace crypto
{
  struct SubjectAltName
  {
    std::string san;
    bool is_ip;

    bool operator==(const SubjectAltName& other) const = default;
    bool operator!=(const SubjectAltName& other) const = default;
  };
  DECLARE_JSON_TYPE(SubjectAltName);
  DECLARE_JSON_REQUIRED_FIELDS(SubjectAltName, san, is_ip);

  // TODO: Delete this type??
  struct CertificateSubjectIdentity
  {
    std::string name;
    std::vector<SubjectAltName> sans = {};

    CertificateSubjectIdentity() = default;
    CertificateSubjectIdentity(
      const std::string& name, const std::vector<SubjectAltName>& sans = {}) :
      name(name),
      sans(sans)
    {}

    bool operator==(const CertificateSubjectIdentity& other) const = default;
    bool operator!=(const CertificateSubjectIdentity& other) const = default;
  };
  DECLARE_JSON_TYPE(CertificateSubjectIdentity);
  DECLARE_JSON_REQUIRED_FIELDS(CertificateSubjectIdentity, sans, name);
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
  auto format(const crypto::SubjectAltName& san, FormatContext& ctx)
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