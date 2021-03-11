// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "../hex.h"
#include "ds/logger.h"

#include <algorithm>
#include <cctype>
#include <doctest/doctest.h>
#include <string>

TEST_CASE("Hex string to and from conversion")
{
  {
    INFO("Simple test");

    std::string valid_hex_str("0123456789abcdef");
    auto data = ds::from_hex(valid_hex_str);
    REQUIRE(data.size() == valid_hex_str.size() / 2);
    REQUIRE(ds::to_hex(data) == valid_hex_str);
  }

  {
    INFO("Invalid length");

    REQUIRE_THROWS(ds::from_hex("a"));
    REQUIRE_THROWS(ds::from_hex("abc"));
    REQUIRE_THROWS(ds::from_hex("abcde"));
  }

  {
    INFO("Uppercase hex string gets lowercased");

    std::string uppercase_hex_str("0123456789ABCDEF");
    std::string lowercase_hex_str = uppercase_hex_str;
    std::transform(
      lowercase_hex_str.begin(),
      lowercase_hex_str.end(),
      lowercase_hex_str.begin(),
      [](unsigned char c) { return std::tolower(c); });

    auto data = ds::from_hex(uppercase_hex_str);
    REQUIRE(data.size() == uppercase_hex_str.size() / 2);
    REQUIRE(ds::to_hex(data) == lowercase_hex_str);
  }
}