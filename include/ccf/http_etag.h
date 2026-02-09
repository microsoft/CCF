// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <regex>
#include <set>
#include <string>

namespace ccf::http
{
  /** Utility class to resolve If-Match and If-None-Match as described
   * in https://www.rfc-editor.org/rfc/rfc9110#field.if-match
   */
  class Matcher
  {
  private:
    /// If-Match header is present and has the value "*"
    bool any_value = false;
    /// If-Match header is present and has specific etag values
    std::set<std::string> if_etags;

  public:
    /** Construct a Matcher from a match header
     *
     * Note: Weak tags are not supported.
     */
    Matcher(const std::string& match_header)
    {
      if (match_header == "*")
      {
        any_value = true;
        return;
      }

      std::regex etag_rx(R"(\"([0-9a-z:-]+)\",?\s*)");
      auto etags_begin =
        std::sregex_iterator(match_header.begin(), match_header.end(), etag_rx);
      auto etags_end = std::sregex_iterator();
      ssize_t last_matched = 0;

      for (std::sregex_iterator i = etags_begin; i != etags_end; ++i)
      {
        if (i->position() != last_matched)
        {
          throw std::runtime_error("Invalid If-Match header");
        }
        const std::smatch& match = *i;
        if_etags.insert(match[1].str());
        last_matched = match.position() + match.length();
      }

      ssize_t last_index_in_header = match_header.size();

      if (last_matched != last_index_in_header || if_etags.empty())
      {
        throw std::runtime_error("Invalid If-Match header");
      }
    }

    /// Check if a given ETag matches the If-Match/If-None-Match header
    [[nodiscard]] bool matches(const std::string& etag) const
    {
      return any_value || if_etags.contains(etag);
    }

    /// Check if the header will match any ETag (*)
    [[nodiscard]] bool is_any() const
    {
      return any_value;
    }
  };
}