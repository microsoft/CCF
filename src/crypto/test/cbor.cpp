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

TEST_CASE("CBOR: unsigned integer 0")
{
  auto cbor_bytes = ccf::ds::from_hex("00");
  auto value = parse(cbor_bytes);

  REQUIRE(value->as_unsigned() == 0);

  const std::string expected_repr = "Unsigned: 0";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: unsigned integer 42")
{
  auto cbor_bytes = ccf::ds::from_hex("182a");
  auto value = parse(cbor_bytes);

  REQUIRE(value->as_unsigned() == 42);

  const std::string expected_repr = "Unsigned: 42";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: unsigned integer 255")
{
  auto cbor_bytes = ccf::ds::from_hex("18ff");
  auto value = parse(cbor_bytes);

  REQUIRE(value->as_unsigned() == 255);

  const std::string expected_repr = "Unsigned: 255";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: unsigned integer 65535")
{
  auto cbor_bytes = ccf::ds::from_hex("19ffff");
  auto value = parse(cbor_bytes);

  REQUIRE(value->as_unsigned() == 65535);

  const std::string expected_repr = "Unsigned: 65535";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: unsigned integer max uint64")
{
  auto cbor_bytes = ccf::ds::from_hex("1bffffffffffffffff");
  auto value = parse(cbor_bytes);

  REQUIRE(value->as_unsigned() == 18446744073709551615ULL);

  const std::string expected_repr = "Unsigned: 18446744073709551615";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: signed integer -1")
{
  auto cbor_bytes = ccf::ds::from_hex("20");
  auto value = parse(cbor_bytes);

  REQUIRE(value->as_signed() == -1);

  const std::string expected_repr = "Signed: -1";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: signed integer -42")
{
  auto cbor_bytes = ccf::ds::from_hex("3829");
  auto value = parse(cbor_bytes);

  REQUIRE(value->as_signed() == -42);

  const std::string expected_repr = "Signed: -42";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: signed integer -1000")
{
  auto cbor_bytes = ccf::ds::from_hex("3903e7");
  auto value = parse(cbor_bytes);

  REQUIRE(value->as_signed() == -1000);

  const std::string expected_repr = "Signed: -1000";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: signed integer min int64")
{
  auto cbor_bytes = ccf::ds::from_hex("3b7fffffffffffffff");
  auto value = parse(cbor_bytes);

  REQUIRE(value->as_signed() == INT64_MIN);

  const std::string expected_repr = "Signed: -9223372036854775808";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: empty string")
{
  auto cbor_bytes = ccf::ds::from_hex("60");
  auto value = parse(cbor_bytes);

  REQUIRE(value->as_string() == "");

  const std::string expected_repr = R"(String: "")";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: string 'hello'")
{
  auto cbor_bytes = ccf::ds::from_hex("6568656c6c6f");
  auto value = parse(cbor_bytes);

  REQUIRE(value->as_string() == "hello");

  const std::string expected_repr = R"(String: "hello")";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: string 'Hello, World!'")
{
  auto cbor_bytes = ccf::ds::from_hex("6d48656c6c6f2c20576f726c6421");
  auto value = parse(cbor_bytes);

  REQUIRE(value->as_string() == "Hello, World!");

  const std::string expected_repr = R"(String: "Hello, World!")";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: empty bytes")
{
  auto cbor_bytes = ccf::ds::from_hex("40");
  auto value = parse(cbor_bytes);

  auto bytes = value->as_bytes();
  REQUIRE(bytes.size() == 0);

  const std::string expected_repr = "Bytes[0]:";

  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: bytes [0,1,2,3]")
{
  auto cbor_bytes = ccf::ds::from_hex("4400010203");
  auto value = parse(cbor_bytes);

  auto bytes = value->as_bytes();
  std::vector<uint8_t> expected{0x00, 0x01, 0x02, 0x03};
  REQUIRE(
    std::equal(expected.begin(), expected.end(), bytes.begin(), bytes.end()));

  const std::string expected_repr = "Bytes[4]: 00010203";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: bytes deadbeef")
{
  auto cbor_bytes = ccf::ds::from_hex("44deadbeef");
  auto value = parse(cbor_bytes);

  auto bytes = value->as_bytes();
  std::vector<uint8_t> expected{0xde, 0xad, 0xbe, 0xef};
  REQUIRE(
    std::equal(expected.begin(), expected.end(), bytes.begin(), bytes.end()));

  const std::string expected_repr = "Bytes[4]: deadbeef";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: simple value false")
{
  auto cbor_bytes = ccf::ds::from_hex("f4");
  auto value = parse(cbor_bytes);

  REQUIRE(value->as_simple() == SimpleValue::False);

  const std::string expected_repr = "Simple: False";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: simple value true")
{
  auto cbor_bytes = ccf::ds::from_hex("f5");
  auto value = parse(cbor_bytes);

  REQUIRE(value->as_simple() == SimpleValue::True);

  const std::string expected_repr = "Simple: True";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: simple value null")
{
  auto cbor_bytes = ccf::ds::from_hex("f6");
  auto value = parse(cbor_bytes);

  REQUIRE(value->as_simple() == SimpleValue::Null);

  const std::string expected_repr = "Simple: Null";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: simple value undefined")
{
  auto cbor_bytes = ccf::ds::from_hex("f7");
  auto value = parse(cbor_bytes);

  REQUIRE(value->as_simple() == 23);

  const std::string expected_repr = "Simple: 23";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: tagged value Tag(9000) with unsigned 42")
{
  auto cbor_bytes = ccf::ds::from_hex("d92328182a");
  auto value = parse(cbor_bytes);

  const auto& item = value->tag_at(9000);
  REQUIRE(item->as_unsigned() == 42);

  const std::string expected_repr = R"(Tagged[9000]:
  Unsigned: 42)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: tagged value Tag(9001) with signed -42")
{
  auto cbor_bytes = ccf::ds::from_hex("d923293829");
  auto value = parse(cbor_bytes);

  const auto& item = value->tag_at(9001);
  REQUIRE(item->as_signed() == -42);

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
    REQUIRE(arr.items[i]->as_unsigned() == i + 1);
  }

  const std::string expected_repr = R"(Array[5]:
  Unsigned: 1
  Unsigned: 2
  Unsigned: 3
  Unsigned: 4
  Unsigned: 5)";
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

  REQUIRE(arr.items[0]->as_unsigned() == 1);

  REQUIRE(arr.items[1]->as_string() == "two");

  auto bytes = arr.items[2]->as_bytes();
  REQUIRE(bytes.size() == 1);
  REQUIRE(bytes[0] == '3');

  REQUIRE(arr.items[3]->as_simple() == SimpleValue::True);

  REQUIRE(arr.items[4]->as_simple() == SimpleValue::Null);

  const std::string expected_repr = R"(Array[5]:
  Unsigned: 1
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

  REQUIRE(arr.items[0]->as_unsigned() == 0);

  REQUIRE(arr.items[1]->as_signed() == -1);

  REQUIRE(arr.items[2]->as_unsigned() == 42);

  REQUIRE(arr.items[3]->as_signed() == -100);

  REQUIRE(arr.items[4]->as_unsigned() == 65535);

  const std::string expected_repr = R"(Array[5]:
  Unsigned: 0
  Signed: -1
  Unsigned: 42
  Signed: -100
  Unsigned: 65535)";
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

    REQUIRE(inner.items[0]->as_unsigned() == i * 2 + 1);
    REQUIRE(inner.items[1]->as_unsigned() == i * 2 + 2);
  }

  const std::string expected_repr = R"(Array[3]:
  Array[2]:
    Unsigned: 1
    Unsigned: 2
  Array[2]:
    Unsigned: 3
    Unsigned: 4
  Array[2]:
    Unsigned: 5
    Unsigned: 6)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: deeply nested array [1, [2, 3], 4, [5, [6, 7]]]")
{
  auto cbor_bytes = ccf::ds::from_hex("8401820203048205820607");
  auto value = parse(cbor_bytes);

  const auto& arr = std::get<Array>(value->value);
  REQUIRE(arr.items.size() == 4);

  REQUIRE(arr.items[0]->as_unsigned() == 1);

  const auto& arr1 = std::get<Array>(arr.items[1]->value);
  REQUIRE(arr1.items.size() == 2);
  REQUIRE(arr1.items[0]->as_unsigned() == 2);
  REQUIRE(arr1.items[1]->as_unsigned() == 3);

  REQUIRE(arr.items[2]->as_unsigned() == 4);

  const auto& arr3 = std::get<Array>(arr.items[3]->value);
  REQUIRE(arr3.items.size() == 2);
  REQUIRE(arr3.items[0]->as_unsigned() == 5);

  const auto& arr3_1 = std::get<Array>(arr3.items[1]->value);
  REQUIRE(arr3_1.items.size() == 2);
  REQUIRE(arr3_1.items[0]->as_unsigned() == 6);
  REQUIRE(arr3_1.items[1]->as_unsigned() == 7);

  const std::string expected_repr = R"(Array[4]:
  Unsigned: 1
  Array[2]:
    Unsigned: 2
    Unsigned: 3
  Unsigned: 4
  Array[2]:
    Unsigned: 5
    Array[2]:
      Unsigned: 6
      Unsigned: 7)";
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
  REQUIRE(arr.items[0]->as_unsigned() == 1);
  REQUIRE(arr.items[1]->as_unsigned() == 2);
  REQUIRE(arr.items[2]->as_unsigned() == 3);

  const std::string expected_repr = R"(Tagged[9100]:
  Array[3]:
    Unsigned: 1
    Unsigned: 2
    Unsigned: 3)";
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

  const std::string expected_repr = "Map[0]:";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: map {1: 'one', 2: 'two', 3: 'three'}")
{
  auto cbor_bytes = ccf::ds::from_hex("a301636f6e65026374776f03657468726565");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 3);

  REQUIRE(value->map_at(make_unsigned(1))->as_string() == "one");
  REQUIRE(value->map_at(make_unsigned(2))->as_string() == "two");
  REQUIRE(value->map_at(make_unsigned(3))->as_string() == "three");

  const std::string expected_repr = R"(Map[3]:
  Key:
    Unsigned: 1
  Value:
    String: "one"
  Key:
    Unsigned: 2
  Value:
    String: "two"
  Key:
    Unsigned: 3
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

  REQUIRE(value->map_at(make_unsigned(0))->as_unsigned() == 100);
  REQUIRE(value->map_at(make_unsigned(1))->as_unsigned() == 200);
  REQUIRE(value->map_at(make_unsigned(2))->as_unsigned() == 300);

  const std::string expected_repr = R"(Map[3]:
  Key:
    Unsigned: 0
  Value:
    Unsigned: 100
  Key:
    Unsigned: 1
  Value:
    Unsigned: 200
  Key:
    Unsigned: 2
  Value:
    Unsigned: 300)";
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
  REQUIRE(map.items[0].second->as_unsigned() == 1);
  REQUIRE(map.items[1].first->as_string() == "b");
  REQUIRE(map.items[1].second->as_unsigned() == 2);
  REQUIRE(map.items[2].first->as_string() == "c");
  REQUIRE(map.items[2].second->as_unsigned() == 3);

  const std::string expected_repr = R"(Map[3]:
  Key:
    String: "a"
  Value:
    Unsigned: 1
  Key:
    String: "b"
  Value:
    Unsigned: 2
  Key:
    String: "c"
  Value:
    Unsigned: 3)";
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

  REQUIRE(value->array_at(0)->as_unsigned() == 1);

  const auto& map = value->array_at(1);
  REQUIRE(map->size() == 1);
  REQUIRE(map->map_at(make_string("a"))->as_unsigned() == 2);

  REQUIRE(value->array_at(2)->as_unsigned() == 3);

  const std::string expected_repr = R"(Array[3]:
  Unsigned: 1
  Map[1]:
    Key:
      String: "a"
    Value:
      Unsigned: 2
  Unsigned: 3)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: array of maps [{'x': 1}, {'y': 2}, {'z': 3}]")
{
  auto cbor_bytes = ccf::ds::from_hex("83a1617801a1617902a1617a03");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 3);

  REQUIRE(value->array_at(0)->size() == 1);
  REQUIRE(value->array_at(0)->map_at(make_string("x"))->as_unsigned() == 1);

  REQUIRE(value->array_at(1)->size() == 1);
  REQUIRE(value->array_at(1)->map_at(make_string("y"))->as_unsigned() == 2);

  REQUIRE(value->array_at(2)->size() == 1);
  REQUIRE(value->array_at(2)->map_at(make_string("z"))->as_unsigned() == 3);

  const std::string expected_repr = R"(Array[3]:
  Map[1]:
    Key:
      String: "x"
    Value:
      Unsigned: 1
  Map[1]:
    Key:
      String: "y"
    Value:
      Unsigned: 2
  Map[1]:
    Key:
      String: "z"
    Value:
      Unsigned: 3)";
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
  REQUIRE(arr->array_at(0)->as_unsigned() == 1);
  REQUIRE(arr->array_at(1)->as_unsigned() == 2);
  REQUIRE(arr->array_at(2)->as_unsigned() == 3);

  const std::string expected_repr = R"(Map[1]:
  Key:
    String: "items"
  Value:
    Array[3]:
      Unsigned: 1
      Unsigned: 2
      Unsigned: 3)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: map with multiple arrays")
{
  auto cbor_bytes = ccf::ds::from_hex("a361618201026162820304616382050682");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 3);

  const auto& arr_a = value->map_at(make_string("a"));
  REQUIRE(arr_a->size() == 2);
  REQUIRE(arr_a->array_at(0)->as_unsigned() == 1);
  REQUIRE(arr_a->array_at(1)->as_unsigned() == 2);

  const auto& arr_b = value->map_at(make_string("b"));
  REQUIRE(arr_b->size() == 2);
  REQUIRE(arr_b->array_at(0)->as_unsigned() == 3);
  REQUIRE(arr_b->array_at(1)->as_unsigned() == 4);

  const auto& arr_c = value->map_at(make_string("c"));
  REQUIRE(arr_c->size() == 2);
  REQUIRE(arr_c->array_at(0)->as_unsigned() == 5);
  REQUIRE(arr_c->array_at(1)->as_unsigned() == 6);

  const std::string expected_repr = R"(Map[3]:
  Key:
    String: "a"
  Value:
    Array[2]:
      Unsigned: 1
      Unsigned: 2
  Key:
    String: "b"
  Value:
    Array[2]:
      Unsigned: 3
      Unsigned: 4
  Key:
    String: "c"
  Value:
    Array[2]:
      Unsigned: 5
      Unsigned: 6)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: tagged map Tag(10000) with {'a': 1, 'b': 2}")
{
  auto cbor_bytes = ccf::ds::from_hex("d92710a26161016162021b");
  auto value = parse(cbor_bytes);

  const auto& item = value->tag_at(10000);
  REQUIRE(item->size() == 2);
  REQUIRE(item->map_at(make_string("a"))->as_unsigned() == 1);
  REQUIRE(item->map_at(make_string("b"))->as_unsigned() == 2);

  const std::string expected_repr = R"(Tagged[10000]:
  Map[2]:
    Key:
      String: "a"
    Value:
      Unsigned: 1
    Key:
      String: "b"
    Value:
      Unsigned: 2)";
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
  REQUIRE(map->map_at(make_string("count"))->as_unsigned() == 42);
  REQUIRE(map->map_at(make_string("label"))->as_string() == "items");
  REQUIRE(map->map_at(make_string("active"))->as_simple() == SimpleValue::True);

  REQUIRE(value->array_at(2)->as_simple() == SimpleValue::Null);

  const std::string expected_repr = R"(Array[3]:
  Simple: True
  Map[3]:
    Key:
      String: "count"
    Value:
      Unsigned: 42
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
  REQUIRE(map->map_at(make_string("id"))->as_unsigned() == 123);
  REQUIRE(map->map_at(make_string("name"))->as_string() == "test");

  REQUIRE(value->array_at(2)->as_string() == "footer");

  const std::string expected_repr = R"(Array[3]:
  String: "header"
  Map[2]:
    Key:
      String: "id"
    Value:
      Unsigned: 123
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

  REQUIRE(value->array_at(0)->as_unsigned() == 1);
  REQUIRE(value->array_at(1)->as_unsigned() == 2);

  const auto& map = value->array_at(2);
  REQUIRE(map->size() == 1);

  const auto& nested_map = map->map_at(make_string("nested"));
  REQUIRE(nested_map->size() == 1);
  REQUIRE(nested_map->map_at(make_string("key"))->as_string() == "value");

  REQUIRE(value->array_at(3)->as_unsigned() == 3);

  const std::string expected_repr = R"(Array[4]:
  Unsigned: 1
  Unsigned: 2
  Map[1]:
    Key:
      String: "nested"
    Value:
      Map[1]:
        Key:
          String: "key"
        Value:
          String: "value"
  Unsigned: 3)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: array [1, Tag(9600, 'tagged'), 3]")
{
  auto cbor_bytes = ccf::ds::from_hex("8301d925806674616767656403");
  auto value = parse(cbor_bytes);

  REQUIRE(value->size() == 3);

  REQUIRE(value->array_at(0)->as_unsigned() == 1);

  const auto& item = value->array_at(1)->tag_at(9600);
  REQUIRE(item->as_string() == "tagged");

  REQUIRE(value->array_at(2)->as_unsigned() == 3);

  const std::string expected_repr = R"(Array[3]:
  Unsigned: 1
  Tagged[9600]:
    String: "tagged"
  Unsigned: 3)";
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

  REQUIRE(value->map_at(make_unsigned(1))->as_string() == "num");
  REQUIRE(value->map_at(make_string("str"))->as_unsigned() == 2);

  const auto bytes_key = ccf::ds::from_hex("6279746573");
  REQUIRE(
    value->map_at(make_bytes(bytes_key))->as_simple() == SimpleValue::True);

  const std::string expected_repr = R"(Map[3]:
  Key:
    Unsigned: 1
  Value:
    String: "num"
  Key:
    String: "str"
  Value:
    Unsigned: 2
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

  REQUIRE(value->map_at(make_string("a"))->as_unsigned() == 1);
  REQUIRE(value->map_at(make_string("b"))->as_string() == "two");

  const auto byte_value = value->map_at(make_string("c"))->as_bytes();
  REQUIRE(byte_value.size() == 1);
  REQUIRE(byte_value[0] == 0x33);

  REQUIRE(value->map_at(make_string("d"))->as_simple() == SimpleValue::False);

  const std::string expected_repr = R"(Map[4]:
  Key:
    String: "a"
  Value:
    Unsigned: 1
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

  const auto& arr0 = value->map_at(make_unsigned(1));
  REQUIRE(arr0->size() == 2);
  REQUIRE(arr0->array_at(0)->as_unsigned() == 10);
  REQUIRE(arr0->array_at(1)->as_unsigned() == 20);

  const auto& arr1 = value->map_at(make_unsigned(2));
  REQUIRE(arr1->size() == 2);
  REQUIRE(arr1->array_at(0)->as_string() == "a");
  REQUIRE(arr1->array_at(1)->as_string() == "b");

  const auto& arr2 = value->map_at(make_unsigned(3));
  REQUIRE(arr2->size() == 2);
  REQUIRE(arr2->array_at(0)->as_bytes()[0] == 'x');
  REQUIRE(arr2->array_at(1)->as_bytes()[0] == 'y');

  const std::string expected_repr = R"(Map[3]:
  Key:
    Unsigned: 1
  Value:
    Array[2]:
      Unsigned: 10
      Unsigned: 20
  Key:
    Unsigned: 2
  Value:
    Array[2]:
      String: "a"
      String: "b"
  Key:
    Unsigned: 3
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

  const auto data1 = value->map_at(make_unsigned(1))->as_bytes();
  REQUIRE(data1.size() == 5);

  const auto data2 = value->map_at(make_unsigned(2))->as_bytes();
  REQUIRE(data2.size() == 5);

  const std::string expected_repr = R"(Map[2]:
  Key:
    Unsigned: 1
  Value:
    Bytes[5]: 6461746131
  Key:
    Unsigned: 2
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

  REQUIRE(arr->array_at(0)->as_unsigned() == 1);

  const auto& nested = arr->array_at(1);
  REQUIRE(nested->size() == 2);
  REQUIRE(nested->array_at(0)->as_unsigned() == 2);
  REQUIRE(nested->array_at(1)->as_unsigned() == 3);

  REQUIRE(arr->array_at(2)->as_unsigned() == 4);

  const std::string expected_repr = R"(Map[1]:
  Key:
    String: "nested"
  Value:
    Array[3]:
      Unsigned: 1
      Array[2]:
        Unsigned: 2
        Unsigned: 3
      Unsigned: 4)";
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
  REQUIRE(nums->array_at(0)->as_unsigned() == 1);
  REQUIRE(nums->array_at(1)->as_unsigned() == 2);
  REQUIRE(nums->array_at(2)->as_unsigned() == 3);

  const auto& strs = value->map_at(make_string("strings"));
  REQUIRE(strs->size() == 2);
  REQUIRE(strs->array_at(0)->as_string() == "a");
  REQUIRE(strs->array_at(1)->as_string() == "b");

  const auto& flags = value->map_at(make_string("flags"));
  REQUIRE(flags->size() == 2);
  REQUIRE(flags->array_at(0)->as_simple() == SimpleValue::True);
  REQUIRE(flags->array_at(1)->as_simple() == SimpleValue::False);

  const std::string expected_repr = R"(Map[3]:
  Key:
    String: "numbers"
  Value:
    Array[3]:
      Unsigned: 1
      Unsigned: 2
      Unsigned: 3
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
  REQUIRE(single->array_at(0)->as_unsigned() == 42);

  const auto& multiple = value->map_at(make_string("multiple"));
  REQUIRE(multiple->size() == 3);
  REQUIRE(multiple->array_at(0)->as_unsigned() == 1);
  REQUIRE(multiple->array_at(1)->as_unsigned() == 2);
  REQUIRE(multiple->array_at(2)->as_unsigned() == 3);

  const std::string expected_repr = R"(Map[3]:
  Key:
    String: "empty"
  Value:
    Array[0]:
  Key:
    String: "single"
  Value:
    Array[1]:
      Unsigned: 42
  Key:
    String: "multiple"
  Value:
    Array[3]:
      Unsigned: 1
      Unsigned: 2
      Unsigned: 3)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}

TEST_CASE("CBOR: large string (100 'A's)")
{
  auto cbor_bytes = ccf::ds::from_hex(
    "786441414141414141414141414141414141414141414141414141414141414141414141"
    "41414141414141414141414141414141414141414141414141414141414141414141414141"
    "4141414141414141414141414141414141414141414141414141414141414141");
  auto value = parse(cbor_bytes);

  auto str = value->as_string();
  REQUIRE(str.size() == 100);
  for (size_t i = 0; i < 100; i++)
  {
    REQUIRE(str[i] == 'A');
  }

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
  REQUIRE(item->array_at(0)->as_unsigned() == 1);
  REQUIRE(item->array_at(1)->as_string() == "two");
  REQUIRE(item->array_at(2)->as_bytes()[0] == 0x33);

  const std::string expected_repr = R"(Tagged[9400]:
  Array[3]:
    Unsigned: 1
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

  const std::string expected_repr = R"(Tagged[20000]:
  Array[2]:
    Map[1]:
      Key:
        String: "x"
      Value:
        Unsigned: 1
    Map[1]:
      Key:
        String: "y"
      Value:
        Unsigned: 2)";
  const std::string result = to_string(value);
  REQUIRE(result == expected_repr);
}
TEST_CASE("CBOR: helper function make_unsigned")
{
  auto value = make_unsigned(42);
  REQUIRE(value != nullptr);
  REQUIRE(value->as_unsigned() == 42);

  const std::string expected_repr = "Unsigned: 42";
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

TEST_CASE("CBOR: back and forth (un)signed")
{
  auto cbor_bytes = ccf::ds::from_hex("820120");
  auto value = parse(cbor_bytes);

  {
    auto s = make_signed(64);
    REQUIRE(s->as_signed() == 64);
    REQUIRE(s->as_unsigned() == 64);
  }

  {
    auto u = make_unsigned(64);
    REQUIRE(u->as_unsigned() == 64);
    REQUIRE(u->as_signed() == 64);
  }

  {
    auto s = make_signed(-64);
    REQUIRE(s->as_signed() == -64);
    REQUIRE_THROWS_AS((void)s->as_unsigned(), CBORDecodeError);
  }

  {
    const auto value = 1ull + std::numeric_limits<int64_t>::max();
    auto u = make_unsigned(value);
    REQUIRE(u->as_unsigned() == value);
    REQUIRE_THROWS_AS((void)u->as_signed(), CBORDecodeError);
  }
}

TEST_CASE("CBOR: back and forth (un)signed")
{
  auto cbor_bytes = ccf::ds::from_hex(
    "A320622D311B7FFFFFFFFFFFFFFF73393232333337323033363835343737353830371B80"
    "00"
    "0000000000007339323233333732303336383534373735383038");
  auto value = parse(cbor_bytes);

  // Signed only
  REQUIRE(value->map_at(make_signed(-1))->as_string() == "-1");

  // Both have to match
  REQUIRE(
    value->map_at(make_signed(9223372036854775807ll))->as_string() ==
    "9223372036854775807");

  REQUIRE(
    value->map_at(make_unsigned(9223372036854775807ull))->as_string() ==
    "9223372036854775807");

  // Unsigned only
  REQUIRE(
    value->map_at(make_unsigned(9223372036854775808ull))->as_string() ==
    "9223372036854775808");
}

TEST_CASE("CBOR: throw with context")
{
  auto v = make_signed(105);

  const std::string context = "Custom enough context";
  const std::string err = "Not a string value";
  const std::string expected_err = err + ": " + context;
  REQUIRE_THROWS_WITH_AS(
    rethrow_with_context([&]() { std::ignore = v->as_string(); }, context),
    expected_err.c_str(),
    CBORDecodeError);
}