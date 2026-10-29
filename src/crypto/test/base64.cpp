// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/crypto/base64.h"

#include "crypto/openssl/base64.h"

#include <algorithm>
#include <chrono>
#include <doctest/doctest.h>
#include <optional>
#include <random>
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

  // Whole groups, partial groups and extra padding are all rejected
  for (const std::string trailing : {"AQID", "A", "AA", "AAA", "=", "AQ=="})
  {
    INFO("trailing = " << trailing);
    REQUIRE_THROWS_AS(raw_from_b64(encoded + trailing), std::invalid_argument);
  }

  // Trailing whitespace after padding is still accepted
  REQUIRE(raw_from_b64(encoded + "\n") == raw);
  REQUIRE(raw_from_b64(encoded + " \r\n\t") == raw);
}

TEST_CASE("base64 end marker across OpenSSL updates")
{
  // OpenSSL treats '-' as an end-of-content marker and ignores whatever
  // follows it in the same call. Following chunks must not be decoded.
  const std::string ignored(BASE64_MAX_UPDATE_SIZE, 'x');
  REQUIRE(
    raw_from_b64("AQID-" + ignored + "AQID") == std::vector<uint8_t>{1, 2, 3});
  REQUIRE(
    raw_from_b64("AQI=-" + ignored + "AQID") == std::vector<uint8_t>{1, 2});

  // The marker may also follow padding which ended a chunk
  const std::vector<uint8_t> raw(BASE64_MAX_UPDATE_SIZE / 4 * 3 - 1, 0xAB);
  const auto encoded = b64_from_raw(raw.data(), raw.size());
  REQUIRE(encoded.size() == BASE64_MAX_UPDATE_SIZE);
  REQUIRE(raw_from_b64(encoded + "-" + ignored) == raw);
  REQUIRE(raw_from_b64(encoded + "\n-" + ignored) == raw);
  REQUIRE_THROWS_AS(raw_from_b64(encoded + "A-"), std::invalid_argument);
}

TEST_CASE("base64 chunked decoding matches a single OpenSSL call")
{
  // For any input and any chunk size, decoding in chunks must accept or
  // reject exactly as a single call does, and produce the same bytes. The
  // alphabet includes padding, the end marker, whitespace and an invalid
  // character, so that chunk boundaries fall on every kind of state change.
  static constexpr std::string_view alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    "====----\n\n\r\t  !";
  std::mt19937 rng(42);
  std::uniform_int_distribution<size_t> pick_char(0, alphabet.size() - 1);
  std::uniform_int_distribution<size_t> pick_len(0, 140);

  auto decode = [](
                  const std::string& input,
                  size_t chunk_size) -> std::optional<std::vector<uint8_t>> {
    try
    {
      return Base64_openssl::raw_from_b64(input, chunk_size);
    }
    catch (const std::exception&)
    {
      return std::nullopt;
    }
  };

  size_t accepted = 0;
  for (size_t i = 0; i < 20000; ++i)
  {
    std::string input(pick_len(rng), ' ');
    // Half the inputs are a valid encoding, possibly with a suffix
    if (i % 2 == 0)
    {
      std::vector<uint8_t> raw(input.size() / 2);
      std::generate(raw.begin(), raw.end(), [&]() { return rng() & 0xff; });
      input = b64_from_raw(raw.data(), raw.size());
      for (size_t j = 0, n = rng() % 4; j < n; ++j)
      {
        input.push_back(alphabet[pick_char(rng)]);
      }
    }
    else
    {
      for (auto& c : input)
      {
        c = alphabet[pick_char(rng)];
      }
    }

    const auto expected = decode(input, SIZE_MAX);
    accepted += expected.has_value() ? 1 : 0;
    for (size_t chunk_size = 1; chunk_size <= 9; ++chunk_size)
    {
      INFO("input = " << input << ", chunk_size = " << chunk_size);
      REQUIRE(decode(input, chunk_size) == expected);
    }
  }
  // Both outcomes must be well represented for the comparison to mean much
  REQUIRE(accepted > 2000);
  REQUIRE(accepted < 18000);
}

TEST_CASE("base64 chunked encoding matches a single OpenSSL call")
{
  std::mt19937 rng(42);
  for (size_t length = 0; length < 200; ++length)
  {
    std::vector<uint8_t> raw(length);
    std::generate(raw.begin(), raw.end(), [&]() { return rng() & 0xff; });
    const auto expected =
      Base64_openssl::b64_from_raw(raw.data(), raw.size(), SIZE_MAX);
    REQUIRE(expected == reference_b64(raw));
    for (size_t chunk_size = 1; chunk_size <= 9; ++chunk_size)
    {
      INFO("length = " << length << ", chunk_size = " << chunk_size);
      REQUIRE(
        Base64_openssl::b64_from_raw(raw.data(), raw.size(), chunk_size) ==
        expected);
    }
  }
}
