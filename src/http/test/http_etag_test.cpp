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
  http::IfMatch im(std::nullopt);
  REQUIRE(im.is_noop());
  REQUIRE(im.matches(""));
  REQUIRE(im.matches("abc"));
}

TEST_CASE("If-Match: *")
{
  http::IfMatch im("*");
  REQUIRE(!im.is_noop());
  REQUIRE(im.matches(""));
  REQUIRE(im.matches("abc"));
}

TEST_CASE("If-Match: \"abc\"")
{
  http::IfMatch im("\"abc\"");
  REQUIRE(!im.is_noop());
  REQUIRE(!im.matches(""));
  REQUIRE(im.matches("abc"));
  REQUIRE(!im.matches("def"));
}

TEST_CASE("If-Match: \"abc\", \"def\"")
{
  http::IfMatch im("\"abc\", \"def\"");
  REQUIRE(!im.is_noop());
  REQUIRE(!im.matches(""));
  REQUIRE(im.matches("abc"));
  REQUIRE(im.matches("def"));
  REQUIRE(!im.matches("ghi"));
}