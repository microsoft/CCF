// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <string>

namespace ccf::endpoints
{
  std::string camel_case(
    std::string s,
    // Should the first character be upper-cased?
    bool camel_first = true,
    // Regex fragment to identify which characters should be upper-cased, by
    // matching a separator preceding them. Default is to match any
    // non-alphanumeric character
    const std::string& separator_regex = "[^[:alnum:]]");
}