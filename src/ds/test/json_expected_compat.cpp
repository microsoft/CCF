// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Exercise a header previously included while its declarations were disabled.
#include <expected>

constexpr auto concepts_before_json = __cpp_concepts;

#include "ccf/json.h"

#include <doctest/doctest.h>
#include <memory>
#include <string>

static_assert(__cpp_concepts == concepts_before_json);
static_assert(*std::expected<int, int>{7} == 7);

TEST_CASE("Glaze uses the standard expected without leaking compiler macros")
{
  static_assert(
    std::is_same_v<glz::expected<int, int>, std::expected<int, int>>);
  const auto good = glz::read_json<int>(std::string{"7"});
  const auto bad = glz::read_json<int>(std::string{"{"});
  REQUIRE(good.has_value());
  CHECK(*good == 7);
  CHECK_FALSE(bad.has_value());
  CHECK(static_cast<bool>(bad.error()));

  std::expected<std::string, std::string> value{"value"};
  const auto copy = value;
  value = std::unexpected{std::string{"error"}};
  CHECK(value.error() == "error");
  value = copy;
  CHECK(*value == "value");

  std::expected<std::unique_ptr<int>, std::string> move_only{
    std::make_unique<int>(9)};
  const auto moved = std::move(move_only);
  CHECK(**moved == 9);
  CHECK_THROWS_AS(bad.value(), std::bad_expected_access<glz::error_ctx>);
}
