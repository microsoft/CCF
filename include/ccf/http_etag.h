// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <regex>
#include <set>
#include <string>

namespace http
{
  // https://www.rfc-editor.org/rfc/rfc9110#field.if-match
  class IfMatch
  {
  private:
    bool noop = false;
    bool any_value = false;
    std::set<std::string> if_etags;

  public:
    IfMatch(const std::optional<std::string>& if_match_header)
    {
      if (!if_match_header.has_value())
      {
        noop = true;
        return;
      }

      if (if_match_header.value() == "*")
      {
        any_value = true;
        return;
      }

      std::regex etag_rx("\\\"([0-9a-f]+)\\\",?\\s*");
      auto etags_begin = std::sregex_iterator(
        if_match_header.value().begin(),
        if_match_header.value().end(),
        etag_rx);
      auto etags_end = std::sregex_iterator();
      for (std::sregex_iterator i = etags_begin; i != etags_end; ++i)
      {
        std::smatch match = *i;
        if_etags.insert(match[1].str());
      }

      if (if_etags.empty() && !any_value)
      {
        throw std::runtime_error("Invalid If-Match header");
      }
    }

    bool matches(const std::string& val) const
    {
      if (noop)
      {
        return true;
      }

      return any_value || if_etags.contains(val);
    }

    bool matches(const std::optional<std::string>& val) const
    {
      if (!val.has_value())
      {
        return false;
      }

      return matches(val.value());
    }

    bool is_noop() const
    {
      return noop;
    }
  };
}