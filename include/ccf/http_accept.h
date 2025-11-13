// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/nonstd.h"
#include "ccf/http_status.h"
#include "ccf/odata_error.h"
#include "ccf/rpc_exception.h"

#include <string_view>

namespace ccf::http
{
  struct AcceptHeaderField
  {
    std::string mime_type;
    std::string mime_subtype;
    float q_factor;

    static bool is_wildcard(const std::string_view& s)
    {
      return s == "*";
    }

    [[nodiscard]] bool matches(const std::string& mime) const
    {
      const auto [t, st] = ccf::nonstd::split_1(mime, "/");

      if (is_wildcard(mime_type) || mime_type == t)
      {
        if (is_wildcard(mime_subtype) || mime_subtype == st)
        {
          return true;
        }
      }

      return false;
    }

    bool operator==(const AcceptHeaderField& other) const
    {
      return mime_type == other.mime_type &&
        mime_subtype == other.mime_subtype && q_factor == other.q_factor;
    }

    bool operator<(const AcceptHeaderField& other) const
    {
      static constexpr auto float_comp_epsilon = 0.0000001f;
      if (std::abs(q_factor - other.q_factor) > float_comp_epsilon)
      {
        return q_factor < other.q_factor;
      }

      if (is_wildcard(mime_type) && !is_wildcard(other.mime_type))
      {
        return true;
      }

      if (is_wildcard(mime_subtype) && !is_wildcard(other.mime_subtype))
      {
        return true;
      }

      // Spec says these mime types are now equivalent. For stability, we
      // order them lexicographically
      if (mime_type != other.mime_type)
      {
        return mime_type < other.mime_type;
      }
      return mime_subtype < other.mime_subtype;
    }
  };

  inline std::vector<AcceptHeaderField> parse_accept_header(std::string s)
  {
    // Strip out all spaces
    s.erase(
      std::remove_if(s.begin(), s.end(), [](char c) { return c == ' '; }),
      s.end());

    if (s.empty())
    {
      return {};
    }

    std::vector<AcceptHeaderField> fields;

    const auto elements = ccf::nonstd::split(s, ",");
    for (const auto& element : elements)
    {
      const auto [types, q_string] = ccf::nonstd::split_1(element, ";q=");
      const auto [type, subtype] = ccf::nonstd::split_1(types, "/");
      if (type.empty() || subtype.empty())
      {
        throw ccf::RpcException(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidHeaderValue,
          fmt::format(
            "Entry in Accept header is not a valid MIME type: {}", element));
      }

      float q_factor = 1.0f;
      if (!q_string.empty())
      {
        try
        {
          q_factor = std::stof(std::string(q_string));
        }
        catch (const std::exception& e)
        {
          throw ccf::RpcException(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidHeaderValue,
            fmt::format(
              "Could not parse q-factor from MIME type in Accept header: "
              "{}",
              element));
        }
      }

      fields.push_back(
        AcceptHeaderField{std::string(type), std::string(subtype), q_factor});
    }

    // Sort in _reverse_, so the 'largest' (highest quality-value) entry is
    // first
    std::sort(fields.begin(), fields.end(), [](const auto& a, const auto& b) {
      return b < a;
    });
    return fields;
  }
}