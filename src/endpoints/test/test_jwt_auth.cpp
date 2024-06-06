// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "ccf/endpoints/authentication/jwt_auth.h"

#include <doctest/doctest.h>

using namespace ccf;

TEST_CASE("Validate JWT issuer")
{
  REQUIRE_FALSE(validate_issuer("https://example.issuer", std::nullopt, ""));
  REQUIRE_FALSE(
    validate_issuer("https://example.issuer", "", "https://example.issuer"));
  REQUIRE_FALSE(validate_issuer(
    "https://example.issuer",
    "https://example.issuer",
    "https://example.issuer"));
  REQUIRE_FALSE(validate_issuer(
    "https://login.microsoftonline.com/{tenantid}/v2.0",
    "deadbeef",
    "https://login.microsoftonline.com/deadbeef/v2.0"));
  REQUIRE_FALSE(validate_issuer(
    "https://login.microsoftonline.com/deadbeef/v2.0",
    std::nullopt,
    "https://login.microsoftonline.com/deadbeef/v2.0"));
  REQUIRE_FALSE(validate_issuer(
    "https://login.microsoftonline.com/deadbeef/v2.0",
    "",
    "https://login.microsoftonline.com/deadbeef/v2.0"));
  REQUIRE_FALSE(validate_issuer(
    "https://login.microsoftonline.com/deadbeef/v2.0", "deadbeef", ""));

  REQUIRE(validate_issuer(
    "https://example.issuer", std::nullopt, "https://example.issuer"));
  REQUIRE(validate_issuer(
    "https://login.microsoftonline.com/deadbeef/v2.0",
    "deadbeef",
    "https://login.microsoftonline.com/deadbeef/v2.0"));
}
