// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <regex>
#include <set>
#include <string>

namespace ccf
{
  namespace http
  {
    /** Utility class to resolve If-Match and If-None-Match as described
     * in https://www.rfc-editor.org/rfc/rfc9110#field.if-match
     */
    class Matcher
    {
    private:
      /// If-Match header is not present
      bool _empty = false;
      /// If-Match header is present and has the value "*"
      bool any_value = false;
      /// If-Match header is present and has specific etag values
      std::set<std::string> if_etags;

    public:
      /** Construct a Matcher from a match header if present
       *
       * Note: Weak tags are not supported.
       */
      Matcher(const std::optional<std::string>& match_header)
      {
        if (!match_header.has_value())
        {
          _empty = true;
          return;
        }

        if (match_header.value() == "*")
        {
          any_value = true;
          return;
        }

        std::regex etag_rx("\\\"([0-9a-f]+)\\\",?\\s*");
        auto etags_begin = std::sregex_iterator(
          match_header.value().begin(), match_header.value().end(), etag_rx);
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

        ssize_t last_index_in_header = match_header.value().size();

        if (last_matched != last_index_in_header || if_etags.empty())
        {
          throw std::runtime_error("Invalid If-Match header");
        }
      }

      /// Check if a given ETag matches the If-Match/If-None-Match header
      bool matches(const std::string& etag) const
      {
        if (_empty)
        {
          return true;
        }

        return any_value || if_etags.contains(etag);
      }

      /// Check if the header is empty
      bool empty() const
      {
        return _empty;
      }

      /// Check if the header will match any ETag (*)
      bool is_any() const
      {
        return any_value;
      }
    };
  }
}