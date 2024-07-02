// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/crypto/base64.h"

#include <chrono>
#include <doctest/doctest.h>
#include <string>

using namespace std;
using namespace ccf::crypto;

static constexpr auto MAX_LEN = 2000;

TEST_CASE("base64 explicit")
{
  using Vec = std::vector<uint8_t>;

  REQUIRE(b64_from_raw(Vec{}) == "");
  REQUIRE(raw_from_b64("") == Vec{});
  REQUIRE(raw_from_b64url("") == Vec{});

  const Vec raw{1, 2, 3, 4, 5, 6, 7, 8};
  REQUIRE(b64_from_raw(raw) == "AQIDBAUGBwg=");
  REQUIRE(b64_from_raw(raw.data(), 0) == "");
  REQUIRE(b64_from_raw(raw.data(), 1) == "AQ==");
  REQUIRE(b64_from_raw(raw.data(), 2) == "AQI=");
  REQUIRE(b64_from_raw(raw.data(), 3) == "AQID");
  REQUIRE(b64_from_raw(raw.data(), 4) == "AQIDBA==");
  REQUIRE(b64_from_raw(raw.data(), 5) == "AQIDBAU=");
  REQUIRE(b64_from_raw(raw.data(), 6) == "AQIDBAUG");
  REQUIRE(b64_from_raw(raw.data(), 7) == "AQIDBAUGBw==");
  REQUIRE(b64_from_raw(raw.data(), 8) == "AQIDBAUGBwg=");

  REQUIRE(raw_from_b64("AQIDBAUGBwg=") == raw);
  REQUIRE(raw_from_b64("") == Vec{});
  REQUIRE_THROWS(raw_from_b64("="));
  REQUIRE_THROWS(raw_from_b64("=="));
  REQUIRE_THROWS(raw_from_b64("==="));
  REQUIRE_THROWS(raw_from_b64("===="));
  REQUIRE_THROWS(raw_from_b64("====="));
  REQUIRE_THROWS(raw_from_b64("A"));
  REQUIRE_THROWS(raw_from_b64("A="));
  REQUIRE_THROWS(raw_from_b64("A=="));
  REQUIRE_THROWS(raw_from_b64("A==="));
  REQUIRE_THROWS(raw_from_b64("A===="));
  REQUIRE_THROWS(raw_from_b64("AQ"));
  REQUIRE_THROWS(raw_from_b64("AQ="));
  REQUIRE(raw_from_b64("AQ==") == Vec{1});
  REQUIRE_THROWS(raw_from_b64("AQ==="));
  REQUIRE_THROWS(raw_from_b64("AQ===="));
  REQUIRE(raw_from_b64("AQI=") == Vec{1, 2});
  REQUIRE(raw_from_b64("AQID") == Vec{1, 2, 3});
  REQUIRE(raw_from_b64("AQIDBA==") == Vec{1, 2, 3, 4});
  REQUIRE(raw_from_b64("AQIDBAU=") == Vec{1, 2, 3, 4, 5});
  REQUIRE(raw_from_b64("AQIDBAUG") == Vec{1, 2, 3, 4, 5, 6});
  REQUIRE(raw_from_b64("AQIDBAUGBw==") == Vec{1, 2, 3, 4, 5, 6, 7});
  REQUIRE(raw_from_b64("AQIDBAUGBwg=") == Vec{1, 2, 3, 4, 5, 6, 7, 8});

  REQUIRE(raw_from_b64url("AQIDBAUGBwg=") == raw);
  REQUIRE(raw_from_b64url("") == Vec{});
  REQUIRE_THROWS(raw_from_b64url("="));
  REQUIRE_THROWS(raw_from_b64url("=="));
  REQUIRE_THROWS(raw_from_b64url("==="));
  REQUIRE_THROWS(raw_from_b64url("===="));
  REQUIRE_THROWS(raw_from_b64url("====="));
  REQUIRE_THROWS(raw_from_b64url("A"));
  REQUIRE_THROWS(raw_from_b64url("A="));
  REQUIRE_THROWS(raw_from_b64url("A=="));
  REQUIRE_THROWS(raw_from_b64url("A==="));
  REQUIRE_THROWS(raw_from_b64url("A===="));
  REQUIRE(raw_from_b64url("AQ") == Vec{1});
  REQUIRE(raw_from_b64url("AQ=") == Vec{1});
  REQUIRE(raw_from_b64url("AQ==") == Vec{1});
  REQUIRE_THROWS(raw_from_b64url("AQ==="));
  REQUIRE(raw_from_b64url("AQI=") == Vec{1, 2});
  REQUIRE(raw_from_b64url("AQID") == Vec{1, 2, 3});
  REQUIRE(raw_from_b64url("AQIDBA==") == Vec{1, 2, 3, 4});
  REQUIRE(raw_from_b64url("AQIDBAU=") == Vec{1, 2, 3, 4, 5});
  REQUIRE(raw_from_b64url("AQIDBAUG") == Vec{1, 2, 3, 4, 5, 6});
  REQUIRE(raw_from_b64url("AQIDBAUGBw==") == Vec{1, 2, 3, 4, 5, 6, 7});
  REQUIRE(raw_from_b64url("AQIDBAUGBwg=") == Vec{1, 2, 3, 4, 5, 6, 7, 8});

  REQUIRE(
    raw_from_b64url("+/+/++//") == Vec{0xfb, 0xff, 0xbf, 0xfb, 0xef, 0xff});
  REQUIRE(
    raw_from_b64url("+/-_+-/_") == Vec{0xfb, 0xff, 0xbf, 0xfb, 0xef, 0xff});
}

TEST_CASE("base64 random")
{
  for (size_t length = 0; length < MAX_LEN; ++length)
  {
    std::vector<uint8_t> raw(length);
    std::generate(raw.begin(), raw.end(), rand);

    auto encoded = b64_from_raw(raw.data(), raw.size());
    std::vector<uint8_t> decoded;

    SUBCASE("base64url")
    {
      std::replace(encoded.begin(), encoded.end(), '+', '-');
      std::replace(encoded.begin(), encoded.end(), '/', '_');
      encoded.erase(
        std::find(encoded.begin(), encoded.end(), '='), encoded.end());
      decoded = raw_from_b64url(encoded);
    }
    else
    {
      decoded = raw_from_b64(encoded);
    }
    REQUIRE(decoded == raw);
  }
}
