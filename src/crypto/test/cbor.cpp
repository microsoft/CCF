// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "crypto/cbor.h"

#include "ccf/ds/hex.h"

#include <cstdint>
#include <doctest/doctest.h>
#include <iostream>
#include <vector>

using namespace ccf::cbor;

TEST_CASE("CBOR: signed integers")
{
  std::vector<std::tuple<doctest::String, std::string, int64_t, std::string>>
    test_cases{
      {"signed integer -1", "20", -1, "Signed: -1"},
      {"signed integer 1", "01", 1, "Signed: 1"},
      {"signed integer -42", "3829", -42, "Signed: -42"},
      {"signed integer 42", "182a", 42, "Signed: 42"},
      {"signed integer -1000", "3903e7", -1000, "Signed: -1000"},
      {"signed integer 1000", "1903e8", 1000, "Signed: 1000"},
      {"signed integer min int64",
       "3b7fffffffffffffff",
       std::numeric_limits<int64_t>::min(),
       "Signed: -9223372036854775808"},
      {"signed integer max int64",
       "1B7FFFFFFFFFFFFFFF",
       std::numeric_limits<int64_t>::max(),
       "Signed: 9223372036854775807"}};

  for (const auto& [name, hex, expected_value, expected_repr] : test_cases)
  {
    SUBCASE(name)
    {
      auto cbor_bytes = ccf::ds::from_hex(hex);
      auto value = parse(cbor_bytes);

      REQUIRE(value->as_signed() == expected_value);

      auto encoded = serialize(value);
      auto decoded = parse(encoded);
      REQUIRE_EQ(cbor_bytes, encoded);

      REQUIRE(decoded->as_signed() == expected_value);

      const std::string result = to_string(value);
      REQUIRE(result == expected_repr);
    }
  }
}

TEST_CASE("CBOR: signed integer overflow")
{
  // 9223372036854775807 + 1 = 9223372036854775808
  auto cbor_bytes = ccf::ds::from_hex("1b8000000000000000");
  REQUIRE_THROWS_AS(parse(cbor_bytes), CBORDecodeError);
}

TEST_CASE("CBOR: strings")
{
  std::vector<
    std::tuple<doctest::String, std::string, std::string, std::string>>
    test_cases{
      {"empty string", "60", "", R"(String: "")"},
      {"string 'hello'", "6568656c6c6f", "hello", R"(String: "hello")"},
      {"string 'Hello, World!'",
       "6d48656c6c6f2c20576f726c6421",
       "Hello, World!",
       R"(String: "Hello, World!")"}};

  for (const auto& [name, hex, expected_value, expected_repr] : test_cases)
  {
    SUBCASE(name)
    {
      auto cbor_bytes = ccf::ds::from_hex(hex);
      auto value = parse(cbor_bytes);

      REQUIRE(value->as_string() == expected_value);

      auto encoded = serialize(value);
      auto decoded = parse(encoded);
      REQUIRE_EQ(cbor_bytes, encoded);

      REQUIRE(decoded->as_string() == expected_value);

      const std::string result = to_string(value);
      REQUIRE(result == expected_repr);
    }
  }
}

TEST_CASE("CBOR: bytes")
{
  std::vector<
    std::tuple<doctest::String, std::string, std::vector<uint8_t>, std::string>>
    test_cases{
      {"empty bytes", "40", {}, "Bytes[0]:"},
      {"bytes [0,1,2,3]",
       "4400010203",
       {0x00, 0x01, 0x02, 0x03},
       "Bytes[4]: 00010203"},
      {"bytes deadbeef",
       "44deadbeef",
       {0xde, 0xad, 0xbe, 0xef},
       "Bytes[4]: deadbeef"}};

  for (const auto& [name, hex, expected_value, expected_repr] : test_cases)
  {
    SUBCASE(name)
    {
      auto cbor_bytes = ccf::ds::from_hex(hex);
      auto value = parse(cbor_bytes);

      auto bytes = value->as_bytes();
      REQUIRE(std::equal(
        expected_value.begin(),
        expected_value.end(),
        bytes.begin(),
        bytes.end()));

      auto encoded = serialize(value);
      auto decoded = parse(encoded);
      REQUIRE_EQ(cbor_bytes, encoded);

      bytes = decoded->as_bytes();
      REQUIRE(std::equal(
        expected_value.begin(),
        expected_value.end(),
        bytes.begin(),
        bytes.end()));

      const std::string result = to_string(value);
      REQUIRE(result == expected_repr);
    }
  }
}

TEST_CASE("CBOR: simple values")
{
  std::vector<
    std::tuple<doctest::String, std::string, SimpleValue, std::string>>
    test_cases{
      {"simple value false", "f4", SimpleValue::False, "Simple: False"},
      {"simple value true", "f5", SimpleValue::True, "Simple: True"},
      {"simple value null", "f6", SimpleValue::Null, "Simple: Null"},
      {"simple value undefined",
       "f7",
       SimpleValue::Undefined,
       "Simple: Undefined"}};

  for (const auto& [name, hex, expected_value, expected_repr] : test_cases)
  {
    SUBCASE(name)
    {
      auto cbor_bytes = ccf::ds::from_hex(hex);
      auto value = parse(cbor_bytes);

      REQUIRE(value->as_simple() == expected_value);

      auto encoded = serialize(value);
      auto decoded = parse(encoded);
      REQUIRE_EQ(cbor_bytes, encoded);

      REQUIRE(decoded->as_simple() == expected_value);

      const std::string result = to_string(value);
      REQUIRE(result == expected_repr);
    }
  }
}

TEST_CASE("CBOR: tagged value Tag(9001) with signed -42")
{
  auto cbor_bytes = ccf::ds::from_hex("d923293829");
  auto value = parse(cbor_bytes);

  const auto& item = value->tag_at(9001);
  REQUIRE(item->as_signed() == -42);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  REQUIRE_EQ(decoded->tag_at(9001)->as_signed(), -42);

  const std::string expected_repr = R"(Tagged[9001]:
  Signed: -42)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: tagged value Tag(9002) with string")
{
  auto cbor_bytes = ccf::ds::from_hex("d9232a6d74616767656420737472696e67");
  auto value = parse(cbor_bytes);

  const auto& item = value->tag_at(9002);
  REQUIRE(item->as_string() == "tagged string");

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  REQUIRE_EQ(decoded->tag_at(9002)->as_string(), "tagged string");

  const std::string expected_repr = R"(Tagged[9002]:
  String: "tagged string")";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: tagged value Tag(9003) with bytes")
{
  auto cbor_bytes = ccf::ds::from_hex("d9232b42cafe");
  auto value = parse(cbor_bytes);

  const auto& item = value->tag_at(9003);
  auto bytes = item->as_bytes();
  REQUIRE(bytes.size() == 2);
  REQUIRE(bytes[0] == 0xca);
  REQUIRE(bytes[1] == 0xfe);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  auto round_trip_bytes = decoded->tag_at(9003)->as_bytes();
  REQUIRE(std::equal(
    round_trip_bytes.begin(),
    round_trip_bytes.end(),
    bytes.begin(),
    bytes.end()));

  const std::string expected_repr = R"(Tagged[9003]:
  Bytes[2]: cafe)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: tagged value Tag(9004) with boolean")
{
  auto cbor_bytes = ccf::ds::from_hex("d9232cf5");
  auto value = parse(cbor_bytes);

  const auto& item = value->tag_at(9004);
  REQUIRE(item->as_simple() == SimpleValue::True);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  REQUIRE_EQ(decoded->tag_at(9004)->as_simple(), SimpleValue::True);

  const std::string expected_repr = R"(Tagged[9004]:
  Simple: True)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: nested tags Tag(9010, Tag(9020))")
{
  auto cbor_bytes = ccf::ds::from_hex("d92332d9233c666e6573746564");
  auto value = parse(cbor_bytes);

  const auto& outer_item = value->tag_at(9010);
  const auto& inner_item = outer_item->tag_at(9020);
  REQUIRE(inner_item->as_string() == "nested");

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  REQUIRE_EQ(decoded->tag_at(9010)->tag_at(9020)->as_string(), "nested");

  const std::string expected_repr = R"(Tagged[9010]:
  Tagged[9020]:
    String: "nested")";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: empty array")
{
  auto cbor_bytes = ccf::ds::from_hex("80");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 0);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = "Array[0]:";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: array [1, 2, 3, 4, 5]")
{
  auto cbor_bytes = ccf::ds::from_hex("850102030405");
  auto value = parse(cbor_bytes);

  const auto& arr = std::get<Array>(value->value);
  REQUIRE(arr.items.size() == 5);

  for (size_t i = 0; i < 5; i++)
  {
    REQUIRE(arr.items[i]->as_signed() == i + 1);
  }

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  for (size_t i = 0; i < 5; i++)
  {
    REQUIRE_EQ(decoded->array_at(i)->as_signed(), i + 1);
  }

  const std::string expected_repr = R"(Array[5]:
  Signed: 1
  Signed: 2
  Signed: 3
  Signed: 4
  Signed: 5)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: array [-1, -2, -3]")
{
  auto cbor_bytes = ccf::ds::from_hex("83202122");
  auto value = parse(cbor_bytes);

  const auto& arr = std::get<Array>(value->value);
  REQUIRE(arr.items.size() == 3);

  REQUIRE(arr.items[0]->as_signed() == -1);
  REQUIRE(arr.items[1]->as_signed() == -2);
  REQUIRE(arr.items[2]->as_signed() == -3);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  REQUIRE_EQ(decoded->array_at(0)->as_signed(), -1);
  REQUIRE_EQ(decoded->array_at(1)->as_signed(), -2);
  REQUIRE_EQ(decoded->array_at(2)->as_signed(), -3);

  const std::string expected_repr = R"(Array[3]:
  Signed: -1
  Signed: -2
  Signed: -3)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: array ['a', 'b', 'c']")
{
  auto cbor_bytes = ccf::ds::from_hex("83616161626163");
  auto value = parse(cbor_bytes);

  const auto& arr = std::get<Array>(value->value);
  REQUIRE(arr.items.size() == 3);

  REQUIRE(arr.items[0]->as_string() == "a");
  REQUIRE(arr.items[1]->as_string() == "b");
  REQUIRE(arr.items[2]->as_string() == "c");

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  REQUIRE_EQ(decoded->array_at(0)->as_string(), "a");
  REQUIRE_EQ(decoded->array_at(1)->as_string(), "b");
  REQUIRE_EQ(decoded->array_at(2)->as_string(), "c");

  const std::string expected_repr = R"(Array[3]:
  String: "a"
  String: "b"
  String: "c")";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: array [b'x', b'y', b'z']")
{
  auto cbor_bytes = ccf::ds::from_hex("8341784179417a");
  auto value = parse(cbor_bytes);

  const auto& arr = std::get<Array>(value->value);
  REQUIRE(arr.items.size() == 3);

  auto bytes0 = arr.items[0]->as_bytes();
  REQUIRE(bytes0.size() == 1);
  REQUIRE(bytes0[0] == 'x');

  auto bytes1 = arr.items[1]->as_bytes();
  REQUIRE(bytes1.size() == 1);
  REQUIRE(bytes1[0] == 'y');

  auto bytes2 = arr.items[2]->as_bytes();
  REQUIRE(bytes2.size() == 1);
  REQUIRE(bytes2[0] == 'z');

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Array[3]:
  Bytes[1]: 78
  Bytes[1]: 79
  Bytes[1]: 7a)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: array [True, False, None]")
{
  auto cbor_bytes = ccf::ds::from_hex("83f5f4f6");
  auto value = parse(cbor_bytes);

  const auto& arr = std::get<Array>(value->value);
  REQUIRE(arr.items.size() == 3);

  REQUIRE(arr.items[0]->as_simple() == SimpleValue::True);
  REQUIRE(arr.items[1]->as_simple() == SimpleValue::False);
  REQUIRE(arr.items[2]->as_simple() == SimpleValue::Null);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Array[3]:
  Simple: True
  Simple: False
  Simple: Null)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: array [1, 'two', b'3', True, None]")
{
  auto cbor_bytes = ccf::ds::from_hex("85016374776f4133f5f6");
  auto value = parse(cbor_bytes);

  const auto& arr = std::get<Array>(value->value);
  REQUIRE(arr.items.size() == 5);

  REQUIRE(arr.items[0]->as_signed() == 1);

  REQUIRE(arr.items[1]->as_string() == "two");

  auto bytes = arr.items[2]->as_bytes();
  REQUIRE(bytes.size() == 1);
  REQUIRE(bytes[0] == '3');

  REQUIRE(arr.items[3]->as_simple() == SimpleValue::True);

  REQUIRE(arr.items[4]->as_simple() == SimpleValue::Null);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Array[5]:
  Signed: 1
  String: "two"
  Bytes[1]: 33
  Simple: True
  Simple: Null)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: array [0, -1, 42, -100, 65535]")
{
  auto cbor_bytes = ccf::ds::from_hex("850020182a386319ffff");
  auto value = parse(cbor_bytes);

  const auto& arr = std::get<Array>(value->value);
  REQUIRE(arr.items.size() == 5);

  REQUIRE(arr.items[0]->as_signed() == 0);

  REQUIRE(arr.items[1]->as_signed() == -1);

  REQUIRE(arr.items[2]->as_signed() == 42);

  REQUIRE(arr.items[3]->as_signed() == -100);

  REQUIRE(arr.items[4]->as_signed() == 65535);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Array[5]:
  Signed: 0
  Signed: -1
  Signed: 42
  Signed: -100
  Signed: 65535)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: nested array [[1, 2], [3, 4], [5, 6]]")
{
  auto cbor_bytes = ccf::ds::from_hex("83820102820304820506");
  auto value = parse(cbor_bytes);

  const auto& arr = std::get<Array>(value->value);
  REQUIRE(arr.items.size() == 3);

  for (size_t i = 0; i < 3; i++)
  {
    const auto& inner = std::get<Array>(arr.items[i]->value);
    REQUIRE(inner.items.size() == 2);

    REQUIRE(inner.items[0]->as_signed() == i * 2 + 1);
    REQUIRE(inner.items[1]->as_signed() == i * 2 + 2);
  }

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Array[3]:
  Array[2]:
    Signed: 1
    Signed: 2
  Array[2]:
    Signed: 3
    Signed: 4
  Array[2]:
    Signed: 5
    Signed: 6)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: deeply nested array [1, [2, 3], 4, [5, [6, 7]]]")
{
  auto cbor_bytes = ccf::ds::from_hex("8401820203048205820607");
  auto value = parse(cbor_bytes);

  const auto& arr = std::get<Array>(value->value);
  REQUIRE(arr.items.size() == 4);

  REQUIRE(arr.items[0]->as_signed() == 1);

  const auto& arr1 = std::get<Array>(arr.items[1]->value);
  REQUIRE(arr1.items.size() == 2);
  REQUIRE(arr1.items[0]->as_signed() == 2);
  REQUIRE(arr1.items[1]->as_signed() == 3);

  REQUIRE(arr.items[2]->as_signed() == 4);

  const auto& arr3 = std::get<Array>(arr.items[3]->value);
  REQUIRE(arr3.items.size() == 2);
  REQUIRE(arr3.items[0]->as_signed() == 5);

  const auto& arr3_1 = std::get<Array>(arr3.items[1]->value);
  REQUIRE(arr3_1.items.size() == 2);
  REQUIRE(arr3_1.items[0]->as_signed() == 6);
  REQUIRE(arr3_1.items[1]->as_signed() == 7);

  const std::string expected_repr = R"(Array[4]:
  Signed: 1
  Array[2]:
    Signed: 2
    Signed: 3
  Signed: 4
  Array[2]:
    Signed: 5
    Array[2]:
      Signed: 6
      Signed: 7)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: tagged array Tag(9100) with [1, 2, 3]")
{
  auto cbor_bytes = ccf::ds::from_hex("d9238c83010203");
  auto value = parse(cbor_bytes);

  const auto& item = value->tag_at(9100);
  const auto& arr = std::get<Array>(item->value);
  REQUIRE(arr.items.size() == 3);
  REQUIRE(arr.items[0]->as_signed() == 1);
  REQUIRE(arr.items[1]->as_signed() == 2);
  REQUIRE(arr.items[2]->as_signed() == 3);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Tagged[9100]:
  Array[3]:
    Signed: 1
    Signed: 2
    Signed: 3)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: tagged empty array Tag(9300) with []")
{
  auto cbor_bytes = ccf::ds::from_hex("d9245480");
  auto value = parse(cbor_bytes);

  const auto& item = value->tag_at(9300);
  const auto& arr = std::get<Array>(item->value);
  REQUIRE(arr.items.size() == 0);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const auto& array = decoded->tag_at(9300);
  REQUIRE_THROWS_AS((void)array->array_at(0), CBORDecodeError);

  const std::string expected_repr = R"(Tagged[9300]:
  Array[0]:)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: empty map")
{
  auto cbor_bytes = ccf::ds::from_hex("a0");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 0);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = "Map[0]:";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: map {1: 'one', 2: 'two', 3: 'three'}")
{
  auto cbor_bytes = ccf::ds::from_hex("a301636f6e65026374776f03657468726565");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 3);

  REQUIRE(value->map_at(make_signed(1))->as_string() == "one");
  REQUIRE(value->map_at(make_signed(2))->as_string() == "two");
  REQUIRE(value->map_at(make_signed(3))->as_string() == "three");

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  for (size_t i = 0; i < 3; i++)
  {
    REQUIRE_EQ(
      decoded->map_at(make_signed(i + 1))->as_string(),
      value->map_at(make_signed(i + 1))->as_string());
  }

  const std::string expected_repr = R"(Map[3]:
  Key:
    Signed: 1
  Value:
    String: "one"
  Key:
    Signed: 2
  Value:
    String: "two"
  Key:
    Signed: 3
  Value:
    String: "three")";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: map {0: 100, 1: 200, 2: 300}")
{
  auto cbor_bytes = ccf::ds::from_hex("a30018640118c80219012c");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 3);

  REQUIRE(value->map_at(make_signed(0))->as_signed() == 100);
  REQUIRE(value->map_at(make_signed(1))->as_signed() == 200);
  REQUIRE(value->map_at(make_signed(2))->as_signed() == 300);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Map[3]:
  Key:
    Signed: 0
  Value:
    Signed: 100
  Key:
    Signed: 1
  Value:
    Signed: 200
  Key:
    Signed: 2
  Value:
    Signed: 300)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: map {'a': 1, 'b': 2, 'c': 3}")
{
  auto cbor_bytes = ccf::ds::from_hex("a3616101616202616303");
  auto value = parse(cbor_bytes);

  const auto& map = std::get<Map>(value->value);
  REQUIRE(map.items.size() == 3);

  REQUIRE(map.items[0].first->as_string() == "a");
  REQUIRE(map.items[0].second->as_signed() == 1);
  REQUIRE(map.items[1].first->as_string() == "b");
  REQUIRE(map.items[1].second->as_signed() == 2);
  REQUIRE(map.items[2].first->as_string() == "c");
  REQUIRE(map.items[2].second->as_signed() == 3);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Map[3]:
  Key:
    String: "a"
  Value:
    Signed: 1
  Key:
    String: "b"
  Value:
    Signed: 2
  Key:
    String: "c"
  Value:
    Signed: 3)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: map {'x': 'y', 'foo': 'bar'}")
{
  auto cbor_bytes = ccf::ds::from_hex("a26178617963666f6f63626172");
  auto value = parse(cbor_bytes);

  const auto& map = std::get<Map>(value->value);
  REQUIRE(map.items.size() == 2);

  REQUIRE(map.items[0].first->as_string() == "x");
  REQUIRE(map.items[0].second->as_string() == "y");
  REQUIRE(map.items[1].first->as_string() == "foo");
  REQUIRE(map.items[1].second->as_string() == "bar");

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Map[2]:
  Key:
    String: "x"
  Value:
    String: "y"
  Key:
    String: "foo"
  Value:
    String: "bar")";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: map {'enabled': True, 'disabled': False, 'unknown': None}")
{
  auto cbor_bytes = ccf::ds::from_hex(
    "a367656e61626c6564f56864697361626c6564f467756e6b6e6f776ef6");
  auto value = parse(cbor_bytes);

  const auto& map = std::get<Map>(value->value);
  REQUIRE(map.items.size() == 3);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  REQUIRE(map.items[0].first->as_string() == "enabled");
  REQUIRE(map.items[0].second->as_simple() == SimpleValue::True);
  REQUIRE(map.items[1].first->as_string() == "disabled");
  REQUIRE(map.items[1].second->as_simple() == SimpleValue::False);
  REQUIRE(map.items[2].first->as_string() == "unknown");
  REQUIRE(map.items[2].second->as_simple() == SimpleValue::Null);

  const std::string expected_repr = R"(Map[3]:
  Key:
    String: "enabled"
  Value:
    Simple: True
  Key:
    String: "disabled"
  Value:
    Simple: False
  Key:
    String: "unknown"
  Value:
    Simple: Null)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: map {-1: 'minus one', -10: 'minus ten'}")
{
  auto cbor_bytes =
    ccf::ds::from_hex("a220696d696e7573206f6e6529696d696e75732074656e");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 2);

  REQUIRE(value->map_at(make_signed(-1))->as_string() == "minus one");
  REQUIRE(value->map_at(make_signed(-10))->as_string() == "minus ten");

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Map[2]:
  Key:
    Signed: -1
  Value:
    String: "minus one"
  Key:
    Signed: -10
  Value:
    String: "minus ten")";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: array with map [1, {'a': 2}, 3]")
{
  auto cbor_bytes = ccf::ds::from_hex("8301a161610203");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 3);

  REQUIRE(value->array_at(0)->as_signed() == 1);

  const auto& map = value->array_at(1);
  REQUIRE(map->size() == 1);
  REQUIRE(map->map_at(make_string("a"))->as_signed() == 2);

  REQUIRE(value->array_at(2)->as_signed() == 3);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Array[3]:
  Signed: 1
  Map[1]:
    Key:
      String: "a"
    Value:
      Signed: 2
  Signed: 3)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: array of maps [{'x': 1}, {'y': 2}, {'z': 3}]")
{
  auto cbor_bytes = ccf::ds::from_hex("83a1617801a1617902a1617a03");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 3);

  REQUIRE(value->array_at(0)->size() == 1);
  REQUIRE(value->array_at(0)->map_at(make_string("x"))->as_signed() == 1);

  REQUIRE(value->array_at(1)->size() == 1);
  REQUIRE(value->array_at(1)->map_at(make_string("y"))->as_signed() == 2);

  REQUIRE(value->array_at(2)->size() == 1);
  REQUIRE(value->array_at(2)->map_at(make_string("z"))->as_signed() == 3);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Array[3]:
  Map[1]:
    Key:
      String: "x"
    Value:
      Signed: 1
  Map[1]:
    Key:
      String: "y"
    Value:
      Signed: 2
  Map[1]:
    Key:
      String: "z"
    Value:
      Signed: 3)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: map with array {'items': [1, 2, 3]}")
{
  auto cbor_bytes = ccf::ds::from_hex("a1656974656d7383010203");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 1);

  const auto& arr = value->map_at(make_string("items"));
  REQUIRE(arr->size() == 3);
  REQUIRE(arr->array_at(0)->as_signed() == 1);
  REQUIRE(arr->array_at(1)->as_signed() == 2);
  REQUIRE(arr->array_at(2)->as_signed() == 3);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Map[1]:
  Key:
    String: "items"
  Value:
    Array[3]:
      Signed: 1
      Signed: 2
      Signed: 3)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: map with multiple arrays")
{
  auto cbor_bytes = ccf::ds::from_hex("a3616182010261628203046163820506");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 3);

  const auto& arr_a = value->map_at(make_string("a"));
  REQUIRE(arr_a->size() == 2);
  REQUIRE(arr_a->array_at(0)->as_signed() == 1);
  REQUIRE(arr_a->array_at(1)->as_signed() == 2);

  const auto& arr_b = value->map_at(make_string("b"));
  REQUIRE(arr_b->size() == 2);
  REQUIRE(arr_b->array_at(0)->as_signed() == 3);
  REQUIRE(arr_b->array_at(1)->as_signed() == 4);

  const auto& arr_c = value->map_at(make_string("c"));
  REQUIRE(arr_c->size() == 2);
  REQUIRE(arr_c->array_at(0)->as_signed() == 5);
  REQUIRE(arr_c->array_at(1)->as_signed() == 6);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Map[3]:
  Key:
    String: "a"
  Value:
    Array[2]:
      Signed: 1
      Signed: 2
  Key:
    String: "b"
  Value:
    Array[2]:
      Signed: 3
      Signed: 4
  Key:
    String: "c"
  Value:
    Array[2]:
      Signed: 5
      Signed: 6)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: tagged map Tag(10000) with {'a': 1, 'b': 2}")
{
  auto cbor_bytes = ccf::ds::from_hex("d92710a2616101616202");
  auto value = parse(cbor_bytes);

  const auto& item = value->tag_at(10000);
  REQUIRE(item->size() == 2);
  REQUIRE(item->map_at(make_string("a"))->as_signed() == 1);
  REQUIRE(item->map_at(make_string("b"))->as_signed() == 2);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Tagged[10000]:
  Map[2]:
    Key:
      String: "a"
    Value:
      Signed: 1
    Key:
      String: "b"
    Value:
      Signed: 2)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE(
  "CBOR: array [True, {'count': 42, 'label': 'items', 'active': True}, None]")
{
  auto cbor_bytes = ccf::ds::from_hex(
    "83f5a365636f756e74182a656c6162656c656974656d7366616374697665f5f6");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 3);

  REQUIRE(value->array_at(0)->as_simple() == SimpleValue::True);

  const auto& map = value->array_at(1);
  REQUIRE(map->size() == 3);
  REQUIRE(map->map_at(make_string("count"))->as_signed() == 42);
  REQUIRE(map->map_at(make_string("label"))->as_string() == "items");
  REQUIRE(map->map_at(make_string("active"))->as_simple() == SimpleValue::True);

  REQUIRE(value->array_at(2)->as_simple() == SimpleValue::Null);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Array[3]:
  Simple: True
  Map[3]:
    Key:
      String: "count"
    Value:
      Signed: 42
    Key:
      String: "label"
    Value:
      String: "items"
    Key:
      String: "active"
    Value:
      Simple: True
  Simple: Null)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: array ['header', {'id': 123, 'name': 'test'}, 'footer']")
{
  auto cbor_bytes = ccf::ds::from_hex(
    "8366686561646572a2626964187b646e616d65647465737466666f6f746572");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 3);

  REQUIRE(value->array_at(0)->as_string() == "header");

  const auto& map = value->array_at(1);
  REQUIRE(map->size() == 2);
  REQUIRE(map->map_at(make_string("id"))->as_signed() == 123);
  REQUIRE(map->map_at(make_string("name"))->as_string() == "test");

  REQUIRE(value->array_at(2)->as_string() == "footer");

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Array[3]:
  String: "header"
  Map[2]:
    Key:
      String: "id"
    Value:
      Signed: 123
    Key:
      String: "name"
    Value:
      String: "test"
  String: "footer")";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: array [1, 2, {'nested': {'key': 'value'}}, 3]")
{
  auto cbor_bytes =
    ccf::ds::from_hex("840102a1666e6573746564a1636b65796576616c756503");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 4);

  REQUIRE(value->array_at(0)->as_signed() == 1);
  REQUIRE(value->array_at(1)->as_signed() == 2);

  const auto& map = value->array_at(2);
  REQUIRE(map->size() == 1);

  const auto& nested_map = map->map_at(make_string("nested"));
  REQUIRE(nested_map->size() == 1);
  REQUIRE(nested_map->map_at(make_string("key"))->as_string() == "value");

  REQUIRE(value->array_at(3)->as_signed() == 3);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Array[4]:
  Signed: 1
  Signed: 2
  Map[1]:
    Key:
      String: "nested"
    Value:
      Map[1]:
        Key:
          String: "key"
        Value:
          String: "value"
  Signed: 3)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: array [1, Tag(9600, 'tagged'), 3]")
{
  auto cbor_bytes = ccf::ds::from_hex("8301d925806674616767656403");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 3);

  REQUIRE(value->array_at(0)->as_signed() == 1);

  const auto& item = value->array_at(1)->tag_at(9600);
  REQUIRE(item->as_string() == "tagged");

  REQUIRE(value->array_at(2)->as_signed() == 3);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Array[3]:
  Signed: 1
  Tagged[9600]:
    String: "tagged"
  Signed: 3)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: large bytes array (16 bytes)")
{
  auto cbor_bytes = ccf::ds::from_hex("50000102030405060708090a0b0c0d0e0f");
  auto value = parse(cbor_bytes);

  auto bytes = value->as_bytes();
  REQUIRE(bytes.size() == 16);
  for (size_t i = 0; i < 16; i++)
  {
    REQUIRE(bytes[i] == static_cast<uint8_t>(i));
  }

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr =
    "Bytes[16]: 000102030405060708090a0b0c0d0e0f";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: map with mixed key types")
{
  auto cbor_bytes = ccf::ds::from_hex("a301636e756d6373747202456279746573f5");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 3);

  REQUIRE(value->map_at(make_signed(1))->as_string() == "num");
  REQUIRE(value->map_at(make_string("str"))->as_signed() == 2);

  const auto bytes_key = ccf::ds::from_hex("6279746573");
  REQUIRE(
    value->map_at(make_bytes(bytes_key))->as_simple() == SimpleValue::True);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Map[3]:
  Key:
    Signed: 1
  Value:
    String: "num"
  Key:
    String: "str"
  Value:
    Signed: 2
  Key:
    Bytes[5]: 6279746573
  Value:
    Simple: True)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: map {'a': 1, 'b': 'two', 'c': b'3', 'd': False}")
{
  auto cbor_bytes = ccf::ds::from_hex("a461610161626374776f616341336164f4");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 4);

  REQUIRE(value->map_at(make_string("a"))->as_signed() == 1);
  REQUIRE(value->map_at(make_string("b"))->as_string() == "two");

  const auto byte_value = value->map_at(make_string("c"))->as_bytes();
  REQUIRE(byte_value.size() == 1);
  REQUIRE(byte_value[0] == 0x33);

  REQUIRE(value->map_at(make_string("d"))->as_simple() == SimpleValue::False);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Map[4]:
  Key:
    String: "a"
  Value:
    Signed: 1
  Key:
    String: "b"
  Value:
    String: "two"
  Key:
    String: "c"
  Value:
    Bytes[1]: 33
  Key:
    String: "d"
  Value:
    Simple: False)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: map {'key1': b'value1', 'key2': b'value2'}")
{
  auto cbor_bytes =
    ccf::ds::from_hex("a2646b6579314676616c756531646b6579324676616c756532");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 2);

  const auto value1 = value->map_at(make_string("key1"))->as_bytes();
  REQUIRE(value1.size() == 6);

  const auto value2 = value->map_at(make_string("key2"))->as_bytes();
  REQUIRE(value2.size() == 6);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Map[2]:
  Key:
    String: "key1"
  Value:
    Bytes[6]: 76616c756531
  Key:
    String: "key2"
  Value:
    Bytes[6]: 76616c756532)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: map {1: [10, 20], 2: ['a', 'b'], 3: [b'x', b'y']}")
{
  auto cbor_bytes = ccf::ds::from_hex("a301820a14028261616162038241784179");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 3);

  const auto& arr0 = value->map_at(make_signed(1));
  REQUIRE(arr0->size() == 2);
  REQUIRE(arr0->array_at(0)->as_signed() == 10);
  REQUIRE(arr0->array_at(1)->as_signed() == 20);

  const auto& arr1 = value->map_at(make_signed(2));
  REQUIRE(arr1->size() == 2);
  REQUIRE(arr1->array_at(0)->as_string() == "a");
  REQUIRE(arr1->array_at(1)->as_string() == "b");

  const auto& arr2 = value->map_at(make_signed(3));
  REQUIRE(arr2->size() == 2);
  REQUIRE(arr2->array_at(0)->as_bytes()[0] == 'x');
  REQUIRE(arr2->array_at(1)->as_bytes()[0] == 'y');

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Map[3]:
  Key:
    Signed: 1
  Value:
    Array[2]:
      Signed: 10
      Signed: 20
  Key:
    Signed: 2
  Value:
    Array[2]:
      String: "a"
      String: "b"
  Key:
    Signed: 3
  Value:
    Array[2]:
      Bytes[1]: 78
      Bytes[1]: 79)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: map {1: b'data1', 2: b'data2'}")
{
  auto cbor_bytes = ccf::ds::from_hex("a20145646174613102456461746132");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 2);

  const auto data1 = value->map_at(make_signed(1))->as_bytes();
  REQUIRE(data1.size() == 5);

  const auto data2 = value->map_at(make_signed(2))->as_bytes();
  REQUIRE(data2.size() == 5);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Map[2]:
  Key:
    Signed: 1
  Value:
    Bytes[5]: 6461746131
  Key:
    Signed: 2
  Value:
    Bytes[5]: 6461746132)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: map {'nested': [1, [2, 3], 4]}")
{
  auto cbor_bytes = ccf::ds::from_hex("a1666e6573746564830182020304");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 1);

  const auto& arr = value->map_at(make_string("nested"));
  REQUIRE(arr->size() == 3);

  REQUIRE(arr->array_at(0)->as_signed() == 1);

  const auto& nested = arr->array_at(1);
  REQUIRE(nested->size() == 2);
  REQUIRE(nested->array_at(0)->as_signed() == 2);
  REQUIRE(nested->array_at(1)->as_signed() == 3);

  REQUIRE(arr->array_at(2)->as_signed() == 4);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Map[1]:
  Key:
    String: "nested"
  Value:
    Array[3]:
      Signed: 1
      Array[2]:
        Signed: 2
        Signed: 3
      Signed: 4)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: map {'tagged': Tag(9500, 'value')}")
{
  auto cbor_bytes = ccf::ds::from_hex("a166746167676564d9251c6576616c7565");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 1);

  const auto& tagged_value = value->map_at(make_string("tagged"));
  const auto& item = tagged_value->tag_at(9500);
  REQUIRE(item->as_string() == "value");

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Map[1]:
  Key:
    String: "tagged"
  Value:
    Tagged[9500]:
      String: "value")";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE(
  "CBOR: map {'numbers': [1, 2, 3], 'strings': ['a', 'b'], 'flags': [True, "
  "False]}")
{
  auto cbor_bytes = ccf::ds::from_hex(
    "a3676e756d626572738301020367737472696e6773826161616265666c61677382f5f4");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 3);

  const auto& nums = value->map_at(make_string("numbers"));
  REQUIRE(nums->size() == 3);
  REQUIRE(nums->array_at(0)->as_signed() == 1);
  REQUIRE(nums->array_at(1)->as_signed() == 2);
  REQUIRE(nums->array_at(2)->as_signed() == 3);

  const auto& strs = value->map_at(make_string("strings"));
  REQUIRE(strs->size() == 2);
  REQUIRE(strs->array_at(0)->as_string() == "a");
  REQUIRE(strs->array_at(1)->as_string() == "b");

  const auto& flags = value->map_at(make_string("flags"));
  REQUIRE(flags->size() == 2);
  REQUIRE(flags->array_at(0)->as_simple() == SimpleValue::True);
  REQUIRE(flags->array_at(1)->as_simple() == SimpleValue::False);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Map[3]:
  Key:
    String: "numbers"
  Value:
    Array[3]:
      Signed: 1
      Signed: 2
      Signed: 3
  Key:
    String: "strings"
  Value:
    Array[2]:
      String: "a"
      String: "b"
  Key:
    String: "flags"
  Value:
    Array[2]:
      Simple: True
      Simple: False)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: map {'empty': [], 'single': [42], 'multiple': [1, 2, 3]}")
{
  auto cbor_bytes = ccf::ds::from_hex(
    "a365656d707479806673696e676c6581182a686d756c7469706c6583010203");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 3);

  const auto& empty = value->map_at(make_string("empty"));
  REQUIRE(empty->size() == 0);

  const auto& single = value->map_at(make_string("single"));
  REQUIRE(single->size() == 1);
  REQUIRE(single->array_at(0)->as_signed() == 42);

  const auto& multiple = value->map_at(make_string("multiple"));
  REQUIRE(multiple->size() == 3);
  REQUIRE(multiple->array_at(0)->as_signed() == 1);
  REQUIRE(multiple->array_at(1)->as_signed() == 2);
  REQUIRE(multiple->array_at(2)->as_signed() == 3);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Map[3]:
  Key:
    String: "empty"
  Value:
    Array[0]:
  Key:
    String: "single"
  Value:
    Array[1]:
      Signed: 42
  Key:
    String: "multiple"
  Value:
    Array[3]:
      Signed: 1
      Signed: 2
      Signed: 3)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: large string (100 'A's)")
{
  auto cbor_bytes = ccf::ds::from_hex(
    "786441414141414141414141414141414141414141414141414141414141414141414141"
    "41414141414141414141414141414141414141414141414141414141414141414141414141"
    "4141414141414141414141414141414141414141414141414141414141");
  auto value = parse(cbor_bytes);

  auto str = value->as_string();
  REQUIRE(str.size() == 100);
  for (size_t i = 0; i < 100; i++)
  {
    REQUIRE(str[i] == 'A');
  }

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr =
    R"(String: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: tagged array Tag(9200, ['a', 'b', 'c'])")
{
  auto cbor_bytes = ccf::ds::from_hex("d923f083616161626163");
  auto value = parse(cbor_bytes);

  const auto& item = value->tag_at(9200);
  REQUIRE(item->size() == 3);
  REQUIRE(item->array_at(0)->as_string() == "a");
  REQUIRE(item->array_at(1)->as_string() == "b");
  REQUIRE(item->array_at(2)->as_string() == "c");

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Tagged[9200]:
  Array[3]:
    String: "a"
    String: "b"
    String: "c")";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: tagged array Tag(9400, [1, 'two', b'3'])")
{
  auto cbor_bytes = ccf::ds::from_hex("d924b883016374776f4133");
  auto value = parse(cbor_bytes);

  const auto& item = value->tag_at(9400);
  REQUIRE(item->size() == 3);
  REQUIRE(item->array_at(0)->as_signed() == 1);
  REQUIRE(item->array_at(1)->as_string() == "two");
  REQUIRE(item->array_at(2)->as_bytes()[0] == 0x33);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Tagged[9400]:
  Array[3]:
    Signed: 1
    String: "two"
    Bytes[1]: 33)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: tagged array Tag(20000, [{'x': 1}, {'y': 2}])")
{
  auto cbor_bytes = ccf::ds::from_hex("d94e2082a1617801a1617902");
  auto value = parse(cbor_bytes);

  const auto& item = value->tag_at(20000);
  const auto& arr = std::get<Array>(item->value);
  REQUIRE(arr.items.size() == 2);

  auto encoded = serialize(value);
  auto decoded = parse(encoded);
  REQUIRE_EQ(cbor_bytes, encoded);

  const std::string expected_repr = R"(Tagged[20000]:
  Array[2]:
    Map[1]:
      Key:
        String: "x"
      Value:
        Signed: 1
    Map[1]:
      Key:
        String: "y"
      Value:
        Signed: 2)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: helper function make_signed")
{
  auto value = make_signed(42);
  REQUIRE(value != nullptr);
  REQUIRE(value->as_signed() == 42);

  const std::string expected_repr = "Signed: 42";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: helper function make_signed")
{
  auto value = make_signed(-42);
  REQUIRE(value != nullptr);
  REQUIRE(value->as_signed() == -42);

  const std::string expected_repr = "Signed: -42";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: helper function make_string")
{
  auto value = make_string("hello");
  REQUIRE(value != nullptr);
  REQUIRE(value->as_string() == "hello");

  const std::string expected_repr = R"(String: "hello")";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: error - invalid data")
{
  auto cbor_bytes = ccf::ds::from_hex("18");
  REQUIRE_THROWS_AS(parse(cbor_bytes), CBORDecodeError);
}

TEST_CASE("CBOR: error - array out of bounds")
{
  auto cbor_bytes = ccf::ds::from_hex("83010203");
  auto value = parse(cbor_bytes);
  REQUIRE_THROWS_AS((void)value->array_at(10), CBORDecodeError);
}

TEST_CASE("CBOR: error - unexpected tag")
{
  auto cbor_bytes = ccf::ds::from_hex("d9232b42cafe"); // Tag 9003
  auto value = parse(cbor_bytes);

  REQUIRE_THROWS_AS((void)value->tag_at(9004), CBORDecodeError);
}

TEST_CASE("CBOR: throw with context")
{
  auto v = make_signed(105);

  const std::string context = "Custom enough context";
  const std::string err = "Not a string value";
  const std::string expected_err = context + ": " + err;
  REQUIRE_THROWS_WITH_AS(
    rethrow_with_msg([&]() { std::ignore = v->as_string(); }, context),
    expected_err.c_str(),
    CBORDecodeError);
}
