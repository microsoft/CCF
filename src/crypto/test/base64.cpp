// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/crypto/base64.h"

#include "crypto/openssl/base64.h"

#include <algorithm>
#include <chrono>
#include <doctest/doctest.h>
#include <string>
#include <vector>

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

// Encodes 3 bytes into 4 characters without the OpenSSL context, so a
// chunked result can be compared against an independent expectation.
static std::string reference_b64(const std::vector<uint8_t>& raw)
{
  static constexpr std::string_view alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out((raw.size() + 2) / 3 * 4, '=');
  size_t o = 0;
  for (size_t i = 0; i < raw.size(); i += 3, o += 4)
  {
    const uint32_t b0 = raw[i];
    const uint32_t b1 = i + 1 < raw.size() ? raw[i + 1] : 0;
    const uint32_t b2 = i + 2 < raw.size() ? raw[i + 2] : 0;
    const uint32_t triple = (b0 << 16) | (b1 << 8) | b2;
    out[o] = alphabet[(triple >> 18) & 0x3f];
    out[o + 1] = alphabet[(triple >> 12) & 0x3f];
    if (i + 1 < raw.size())
    {
      out[o + 2] = alphabet[(triple >> 6) & 0x3f];
    }
    if (i + 2 < raw.size())
    {
      out[o + 3] = alphabet[triple & 0x3f];
    }
  }
  return out;
}

TEST_CASE("base64 inputs spanning several OpenSSL updates")
{
  // Inputs are fed to OpenSSL in chunks of BASE64_MAX_UPDATE_SIZE bytes,
  // which is not a multiple of the encoder's 48-byte group, so every chunk
  // boundary splits a group. The decoder works in 64-character lines, which
  // the chunk size is a multiple of; decoding from an offset covers chunk
  // boundaries inside a line too.
  static_assert(BASE64_MAX_UPDATE_SIZE % 48 != 0);
  static_assert(BASE64_MAX_UPDATE_SIZE % 64 == 0);
  std::vector<uint8_t> raw(BASE64_MAX_UPDATE_SIZE * 2 + 1);
  std::generate(raw.begin(), raw.end(), rand);

  for (const size_t length :
       {BASE64_MAX_UPDATE_SIZE - 1, BASE64_MAX_UPDATE_SIZE + 1, raw.size()})
  {
    INFO("length = " << length);
    const std::vector<uint8_t> input(raw.begin(), raw.begin() + length);
    const auto encoded = b64_from_raw(input.data(), input.size());
    REQUIRE(encoded == reference_b64(input));
    REQUIRE(raw_from_b64(encoded) == input);
    REQUIRE(
      raw_from_b64(encoded.substr(4)) ==
      std::vector<uint8_t>(input.begin() + 3, input.end()));
  }
}

TEST_CASE("base64 rejects data after padding across OpenSSL updates")
{
  // A padded group which ends exactly at a chunk boundary must not let the
  // following chunk be decoded as a fresh string
  const std::vector<uint8_t> raw(BASE64_MAX_UPDATE_SIZE / 4 * 3 - 1, 0xAB);
  auto encoded = b64_from_raw(raw.data(), raw.size());
  REQUIRE(encoded.size() == BASE64_MAX_UPDATE_SIZE);
  REQUIRE(encoded.back() == '=');
  REQUIRE(raw_from_b64(encoded) == raw);

  REQUIRE_THROWS_AS(raw_from_b64(encoded + "AQID"), std::invalid_argument);
  REQUIRE_THROWS_AS(raw_from_b64(encoded + "AQ=="), std::invalid_argument);

  // Trailing whitespace after padding is still accepted
  REQUIRE(raw_from_b64(encoded + "\n") == raw);
}
