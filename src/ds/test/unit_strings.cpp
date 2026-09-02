// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/unit_strings.h"

#include <cmath>
#include <doctest/doctest.h>
#include <limits>

using namespace ccf::ds;

TEST_CASE("Size strings" * doctest::test_suite("unit strings"))
{
  REQUIRE_THROWS(convert_size_string(""));
  REQUIRE_THROWS_AS(convert_size_string("KB"), std::logic_error);
  REQUIRE_THROWS_AS(
    convert_size_string("999999999999999999999999999999999999999999B"),
    std::logic_error);
  REQUIRE_THROWS(convert_size_string("12345INVALIDUNIT"));
  REQUIRE_THROWS(convert_size_string("12345ms"));

  REQUIRE(convert_size_string("0") == 0);
  REQUIRE(convert_size_string("12") == 12);
  REQUIRE(convert_size_string("12B") == 12);
  REQUIRE(convert_size_string("1001") == 1001);
  REQUIRE(convert_size_string("1001B") == 1001);
  REQUIRE(convert_size_string("3KB") == 3 * 1024);
  REQUIRE(convert_size_string("3 KB") == 3 * 1024);
  REQUIRE(convert_size_string("3kb") == 3 * 1024);
  REQUIRE(convert_size_string("3kB") == 3 * 1024);
  REQUIRE(convert_size_string("3Kb") == 3 * 1024);
  REQUIRE(convert_size_string("1024KB") == 1 * std::pow(1024, 2));
  REQUIRE(convert_size_string("3MB") == 3 * std::pow(1024, 2));
  REQUIRE(convert_size_string("3GB") == 3 * std::pow(1024, 3));
  REQUIRE(convert_size_string("3TB") == 3 * std::pow(1024, 4));
  REQUIRE(convert_size_string("3PB") == 3 * std::pow(1024, 5));

  const auto max_size = std::numeric_limits<size_t>::max();
  REQUIRE(convert_size_string(std::to_string(max_size) + "B") == max_size);

  const auto max_kb_value = max_size / 1024;
  REQUIRE(
    convert_size_string(std::to_string(max_kb_value) + "KB") ==
    max_kb_value * 1024);
  REQUIRE_THROWS_AS(
    convert_size_string(std::to_string(max_kb_value + 1) + "KB"),
    std::logic_error);
  REQUIRE_THROWS_AS(
    convert_size_string(std::to_string(max_size) + "PB"), std::logic_error);
}

TEST_CASE("Time strings" * doctest::test_suite("unit strings"))
{
  REQUIRE_THROWS(convert_time_string(""));
  REQUIRE_THROWS_AS(convert_time_string("ms"), std::logic_error);
  REQUIRE_THROWS_AS(
    convert_time_string("999999999999999999999999999999999999999999us"),
    std::logic_error);
  REQUIRE_THROWS(convert_time_string("12345INVALIDUNIT"));
  REQUIRE_THROWS(convert_time_string("12345KB"));

  REQUIRE(convert_time_string("0") == 0);
  REQUIRE(convert_time_string("12") == 12);
  REQUIRE(convert_time_string("12us") == 12);
  REQUIRE(convert_time_string("1001") == 1001);
  REQUIRE(convert_time_string("1001us") == 1001);
  REQUIRE(convert_time_string("3ms") == 3'000);
  REQUIRE(convert_time_string("3 ms") == 3'000);
  REQUIRE(convert_time_string("1234ms") == 1'234'000);
  REQUIRE(convert_time_string("3s") == 3'000'000);
  REQUIRE(convert_time_string("3min") == 60 * convert_time_string("3s"));
  REQUIRE(convert_time_string("3h") == 60 * convert_time_string("3min"));
}

TEST_CASE("Unit string values" * doctest::test_suite("unit strings"))
{
  UnitString empty;
  REQUIRE(empty.str.empty());

  const UnitString value{"1KB"};
  REQUIRE(value.str == "1KB");
  REQUIRE(value == UnitString{"1KB"});
  REQUIRE(value != UnitString{"2KB"});

  nlohmann::json json = value;
  REQUIRE(json == "1KB");
}

TEST_CASE("Size string values" * doctest::test_suite("unit strings"))
{
  const SizeString empty;
  REQUIRE(empty.str.empty());
  REQUIRE(empty.value == 0);

  const SizeString from_literal{"2KB"};
  REQUIRE(from_literal.str == "2KB");
  REQUIRE(static_cast<size_t>(from_literal) == 2 * 1024);
  REQUIRE(from_literal.count_bytes() == 2 * 1024);

  const SizeString from_view{std::string_view{"3MB"}};
  REQUIRE(from_view.str == "3MB");
  REQUIRE(from_view.count_bytes() == 3 * std::pow(1024, 2));

  nlohmann::json json = from_view;
  REQUIRE(json == "3MB");
  const auto from_json = json.get<SizeString>();
  REQUIRE(from_json == from_view);
  REQUIRE(from_json.count_bytes() == from_view.count_bytes());
  REQUIRE_THROWS(nlohmann::json(42).get<SizeString>());

  REQUIRE(schema_name(static_cast<const SizeString*>(nullptr)) == "SizeString");
  nlohmann::json schema;
  fill_json_schema(schema, static_cast<const SizeString*>(nullptr));
  REQUIRE(schema["type"] == "string");
  REQUIRE(schema["pattern"] == "^[0-9]+(B|KB|MB|GB|TB|PB)?$");

  REQUIRE(fmt::format(fmt::runtime("{}"), from_view) == "3MB");
}

TEST_CASE("Time string values" * doctest::test_suite("unit strings"))
{
  const TimeString empty;
  REQUIRE(empty.str.empty());
  REQUIRE(empty.value.count() == 0);

  const TimeString value{"1234567us"};
  REQUIRE(value.str == "1234567us");
  REQUIRE(static_cast<std::chrono::microseconds>(value).count() == 1'234'567);
  REQUIRE(static_cast<std::chrono::milliseconds>(value).count() == 1'234);
  REQUIRE(static_cast<std::chrono::seconds>(value).count() == 1);
  REQUIRE(value.count_ms() == 1'234);
  REQUIRE(value.count_s() == 1);

  nlohmann::json json = value;
  REQUIRE(json == "1234567us");
  const auto from_json = json.get<TimeString>();
  REQUIRE(from_json == value);
  REQUIRE(
    static_cast<std::chrono::microseconds>(from_json).count() == 1'234'567);
  REQUIRE_THROWS(nlohmann::json(42).get<TimeString>());

  REQUIRE(schema_name(static_cast<const TimeString*>(nullptr)) == "TimeString");
  nlohmann::json schema;
  fill_json_schema(schema, static_cast<const TimeString*>(nullptr));
  REQUIRE(schema["type"] == "string");
  REQUIRE(schema["pattern"] == "^[0-9]+(us|ms|s|min|h)?$");
}