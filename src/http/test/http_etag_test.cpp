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
    ccf::http::Matcher im(""), ccf::http::MatcherError, "Invalid If-Match header");
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

TEST_CASE("If-None-Match with algorithm:digest ETag format")
{
  // Single sha-256 ETag
  {
    ccf::http::Matcher im(
      "\"sha-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852"
      "b855\"");
    REQUIRE(!im.is_any());
    REQUIRE(im.matches(
      "sha-256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8"
      "55"));
    REQUIRE(!im.matches("sha-256:0000"));
  }

  // Multiple algorithm ETags
  {
    ccf::http::Matcher im(
      "\"sha-256:aabb\", \"sha-384:ccdd\", \"sha-512:eeff\"");
    REQUIRE(im.matches("sha-256:aabb"));
    REQUIRE(im.matches("sha-384:ccdd"));
    REQUIRE(im.matches("sha-512:eeff"));
    REQUIRE(!im.matches("sha-256:0000"));
  }

  // Wildcard still works
  {
    ccf::http::Matcher im("*");
    REQUIRE(im.is_any());
    REQUIRE(im.matches("sha-256:anything"));
  }
}