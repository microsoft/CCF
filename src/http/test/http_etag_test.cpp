// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/http_etag.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <string>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

TEST_CASE("If-Match missing")
{
  http::Matcher im(std::nullopt);
  REQUIRE(im.empty());
  REQUIRE(im.matches(""));
  REQUIRE(im.matches("abc"));
}

TEST_CASE("If-Match: *")
{
  http::Matcher im("*");
  REQUIRE(!im.empty());
  REQUIRE(im.matches(""));
  REQUIRE(im.matches("abc"));
}

TEST_CASE("If-Match: \"abc\"")
{
  http::Matcher im("\"abc\"");
  REQUIRE(!im.empty());
  REQUIRE(!im.matches(""));
  REQUIRE(im.matches("abc"));
  REQUIRE(!im.matches("def"));
}

TEST_CASE("If-Match: \"abc\", \"def\"")
{
  http::Matcher im("\"abc\", \"def\"");
  REQUIRE(!im.empty());
  REQUIRE(!im.matches(""));
  REQUIRE(im.matches("abc"));
  REQUIRE(im.matches("def"));
  REQUIRE(!im.matches("ghi"));
}

TEST_CASE("If-Match invalid inputs")
{
  REQUIRE_THROWS_AS_MESSAGE(
    http::Matcher im("not etags"),
    std::runtime_error,
    "Invalid If-Match header");
  REQUIRE_THROWS_AS_MESSAGE(
    http::Matcher im("\"abc\", not etags"),
    std::runtime_error,
    "Invalid If-Match header");
  REQUIRE_THROWS_AS_MESSAGE(
    http::Matcher im("not etags, \"abc\""),
    std::runtime_error,
    "Invalid If-Match header");
  REQUIRE_THROWS_AS_MESSAGE(
    http::Matcher im("W/\"abc\""),
    std::runtime_error,
    "Invalid If-Match header");
  REQUIRE_THROWS_AS_MESSAGE(
    http::Matcher im("W/\"abc\", \"def\""),
    std::runtime_error,
    "Invalid If-Match header");
  REQUIRE_THROWS_AS_MESSAGE(
    http::Matcher im("\"abc\", \"def"),
    std::runtime_error,
    "Invalid If-Match header");
  REQUIRE_THROWS_AS_MESSAGE(
    http::Matcher im("\"abc\",, \"def\""),
    std::runtime_error,
    "Invalid If-Match header");
  REQUIRE_THROWS_AS_MESSAGE(
    http::Matcher im(",\"abc\""),
    std::runtime_error,
    "Invalid If-Match header");
}