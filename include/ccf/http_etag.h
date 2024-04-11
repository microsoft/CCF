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
    /// If-Match header is not present
    bool noop = false;
    /// If-Match header is present and has the value "*"
    bool any_value = false;
    /// If-Match header is present and has specific etag values
    std::set<std::string> if_etags;

  public:
    /*
     * If-Match = "*" / #entity-tag
     * entity-tag = [ weak ] opaque-tag
     * weak       = %s"W/"
     * opaque-tag = DQUOTE *etagc DQUOTE
     * etagc      = %x21 / %x23-7E / obs-text
     *            ; VCHAR except double quotes, plus obs-text
     *
     * Note: Weak tags are not supported.
     */
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
      ssize_t last_matched = 0;

      for (std::sregex_iterator i = etags_begin; i != etags_end; ++i)
      {
        if (i->position() != last_matched)
        {
          throw std::runtime_error("Invalid If-Match header");
        }
        std::smatch match = *i;
        if_etags.insert(match[1].str());
        last_matched = match.position() + match.length();
      }

      ssize_t last_index_in_header = if_match_header.value().size();

      if (last_matched != last_index_in_header || if_etags.empty())
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

    bool is_noop() const
    {
      return noop;
    }
  };
}