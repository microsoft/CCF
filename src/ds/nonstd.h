// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include <regex>
#include <string>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ccf::nonstd
{
  static inline std::string expand_envvar(const std::string& str)
  {
    if (str.empty() || str[0] != '$')
    {
      return str;
    }

    char* e = std::getenv(str.c_str() + 1);
    if (e == nullptr)
    {
      return str;
    }
    else
    {
      return std::string(e);
    }
  }

  static inline std::string expand_envvars_in_path(const std::string& str)
  {
    std::filesystem::path path(str);

    if (path.empty())
    {
      return str;
    }

    std::vector<std::filesystem::path> elements;
    auto it = path.begin();
    if (path.has_root_directory())
    {
      ++it;
      elements.push_back(path.root_directory());
    }

    while (it != path.end())
    {
      elements.push_back(expand_envvar(*it++));
    }

    std::filesystem::path resolved;
    for (auto& element : elements)
    {
      resolved /= element;
    }

    return resolved.lexically_normal().string();
  }

  static inline std::string camel_case(
    std::string s,
    // Should the first character be upper-cased?
    bool camel_first = true,
    // Regex fragment to identify which characters should be upper-cased, by
    // matching a separator preceding them. Default is to match any
    // non-alphanumeric character
    const std::string& separator_regex = "[^[:alnum:]]")
  {
    // Replacement is always a 1-character string
    std::string replacement(1, '\0');

    std::string prefix_matcher =
      camel_first ? fmt::format("(^|{})", separator_regex) : separator_regex;
    std::regex re(prefix_matcher + "[a-z]");
    std::smatch match;

    while (std::regex_search(s, match, re))
    {
      // Replacement is the upper-casing of the final character from the match
      replacement[0] = std::toupper(match.str()[match.length() - 1]);

      s = s.replace(match.position(), match.length(), replacement);
    }

    return s;
  }
}
