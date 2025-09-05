// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/hex.h"

#include "ccf/ds/nonstd.h"
#include "ds/framework_logger.h"

#include <algorithm>
#include <cctype>
#include <doctest/doctest.h>
#include <string>

TEST_CASE("Hex string to and from conversion")
{
  {
    INFO("Simple test");

    std::string valid_hex_str("0123456789abcdef");
    auto data = ccf::ds::from_hex(valid_hex_str);
    REQUIRE(data.size() == valid_hex_str.size() / 2);
    REQUIRE(ccf::ds::to_hex(data) == valid_hex_str);
  }

  {
    INFO("Invalid length");

    REQUIRE_THROWS(ccf::ds::from_hex("a"));
    REQUIRE_THROWS(ccf::ds::from_hex("abc"));
    REQUIRE_THROWS(ccf::ds::from_hex("abcde"));
  }

  {
    INFO("Uppercase hex string gets lowercased");

    std::string uppercase_hex_str("0123456789ABCDEF");
    std::string lowercase_hex_str = uppercase_hex_str;
    ccf::nonstd::to_lower(lowercase_hex_str);

    auto data = ccf::ds::from_hex(uppercase_hex_str);
    REQUIRE(data.size() == uppercase_hex_str.size() / 2);
    REQUIRE(ccf::ds::to_hex(data) == lowercase_hex_str);
  }
}
