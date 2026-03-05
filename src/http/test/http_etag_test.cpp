// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/http_etag.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <string>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

TEST_CASE("If-Match: *")
{
  ccf::http::Matcher im("*");
  REQUIRE(im.is_any());
  REQUIRE(im.matches(""));
  REQUIRE(im.matches("abc"));
}

TEST_CASE("If-Match: \"abc\"")
{
  ccf::http::Matcher im("\"abc\"");
  REQUIRE(!im.is_any());
  REQUIRE(!im.matches(""));
  REQUIRE(im.matches("abc"));
  REQUIRE(!im.matches("def"));
}

TEST_CASE("If-Match: \"abc\", \"def\"")
{
  ccf::http::Matcher im("\"abc\", \"def\"");
  REQUIRE(!im.is_any());
  REQUIRE(!im.matches(""));
  REQUIRE(im.matches("abc"));
  REQUIRE(im.matches("def"));
  REQUIRE(!im.matches("ghi"));
}

TEST_CASE("If-Match invalid inputs")
{
  REQUIRE_THROWS_AS_MESSAGE(
    ccf::http::Matcher im(""),
    ccf::http::MatcherError,
    "Invalid If-Match header");
  REQUIRE_THROWS_AS_MESSAGE(
    ccf::http::Matcher im("not etags"),
    ccf::http::MatcherError,
    "Invalid If-Match header");
  REQUIRE_THROWS_AS_MESSAGE(
    ccf::http::Matcher im("\"abc\", not etags"),
    ccf::http::MatcherError,
    "Invalid If-Match header");
  REQUIRE_THROWS_AS_MESSAGE(
    ccf::http::Matcher im("not etags, \"abc\""),
    ccf::http::MatcherError,
    "Invalid If-Match header");
  REQUIRE_THROWS_AS_MESSAGE(
    ccf::http::Matcher im("W/\"abc\""),
    ccf::http::MatcherError,
    "Invalid If-Match header");
  REQUIRE_THROWS_AS_MESSAGE(
    ccf::http::Matcher im("W/\"abc\", \"def\""),
    ccf::http::MatcherError,
    "Invalid If-Match header");
  REQUIRE_THROWS_AS_MESSAGE(
    ccf::http::Matcher im("\"abc\", \"def"),
    ccf::http::MatcherError,
    "Invalid If-Match header");
  REQUIRE_THROWS_AS_MESSAGE(
    ccf::http::Matcher im("\"abc\",, \"def\""),
    ccf::http::MatcherError,
    "Invalid If-Match header");
  REQUIRE_THROWS_AS_MESSAGE(
    ccf::http::Matcher im(",\"abc\""),
    ccf::http::MatcherError,
    "Invalid If-Match header");
}

TEST_CASE("If-None-Match with RFC 9530 digest ETag format")
{
  // Single sha-256 ETag in RFC 9530 structured field format
  {
    ccf::http::Matcher im(
      "\"sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:\"");
    REQUIRE(!im.is_any());
    REQUIRE(
      im.matches("sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"));
    REQUIRE(!im.matches("sha-256=:AAAA:"));
  }

  // Multiple algorithm ETags
  {
    ccf::http::Matcher im(
      "\"sha-256=:abc=:\", \"sha-384=:def=:\", \"sha-512=:ghi=:\"");
    REQUIRE(im.matches("sha-256=:abc=:"));
    REQUIRE(im.matches("sha-384=:def=:"));
    REQUIRE(im.matches("sha-512=:ghi=:"));
    REQUIRE(!im.matches("sha-256=:000=:"));
  }

  // Wildcard still works
  {
    ccf::http::Matcher im("*");
    REQUIRE(im.is_any());
    REQUIRE(im.matches("sha-256=:anything:"));
  }
}