// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.#include "endpoint_utils.h"

#include "endpoint_utils.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <regex>

std::string ccf::endpoints::camel_case(
  std::string s, bool camel_first, const std::string& separator_regex)
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