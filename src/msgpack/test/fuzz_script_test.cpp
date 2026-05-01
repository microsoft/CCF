// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
//
// Canned tests for the fuzz-harness encode_one driver.
//
// encode_one takes a byte-stream "script" and produces (a) an encoded
// msgpack buffer, (b) an nlohmann::json mirror of what was written.
// These tests construct hand-built scripts for nested object/array
// shapes and assert byte-for-byte that the encoded output and the
// returned mirror match expectations, then verify that the JSON
// oracle round-trips the buffer back to the mirror.
//
// The point is to pin down nested-object byte generation: the
// fuzz-driven property check in differential_test.cpp covers the
// happy path probabilistically, but it does not pin specific wire
// bytes for any particular composite shape.

#include "msgpack/encode.h"
#include "msgpack/test/gen.h"

#include <cstdint>
#include <doctest/doctest.h>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace gen = ccf::msgpack::test::gen;
using nlohmann::json;
using ccf::msgpack::FluentdEventTime;

namespace
{
  // Drive encode_one over a given byte script. Returns the encoded
  // buffer alongside the produced mirror.
  struct ScriptResult
  {
    std::vector<uint8_t> buf;
    json mirror;
  };

  ScriptResult run_script(const std::vector<uint8_t>& script)
  {
    gen::StreamReader r(script.data(), script.size());
    std::vector<uint8_t> buf;
    json mirror = gen::encode_one(r, buf);
    return {std::move(buf), std::move(mirror)};
  }

  // 32 zero bytes produce the all-'a' key when consumed by read_key.
  // Returns (the bytes, the resulting key string) for use in scripts.
  struct CannedKey
  {
    std::vector<uint8_t> bytes;
    std::string str;
  };

  CannedKey canned_key_of_char(char ch)
  {
    // ch must be in [a-z]. The byte value that maps to ch under
    // (b % 26) + 'a' is (ch - 'a').
    REQUIRE(ch >= 'a');
    REQUIRE(ch <= 'z');
    const uint8_t b = static_cast<uint8_t>(ch - 'a');
    return CannedKey{
      std::vector<uint8_t>(gen::KEY_LEN, b),
      std::string(gen::KEY_LEN, ch)};
  }

  // Helper: append all bytes from `src` to `dst`.
  void append(std::vector<uint8_t>& dst, const std::vector<uint8_t>& src)
  {
    dst.insert(dst.end(), src.begin(), src.end());
  }
}

// ===== Atoms =====

TEST_CASE("encode_one: nil at top level")
{
  // Op 0 = nil. Expected wire: 0xC0. Mirror: null.
  auto [buf, mirror] = run_script({0});
  CHECK(buf == std::vector<uint8_t>{0xC0});
  CHECK(mirror == json(nullptr));
  CHECK(json::from_msgpack(buf) == mirror);
}

TEST_CASE("encode_one: empty array at top level")
{
  // Op 8 = array, length byte 0 -> n=0. Expected wire: 0x90 (fixarray, 0 elts).
  auto [buf, mirror] = run_script({8, 0});
  CHECK(buf == std::vector<uint8_t>{0x90});
  CHECK(mirror == json::array());
  CHECK(json::from_msgpack(buf) == mirror);
}

TEST_CASE("encode_one: empty object at top level")
{
  // Op 9 = map, length byte 0 -> n=0. Expected wire: 0x80 (fixmap, 0 entries).
  auto [buf, mirror] = run_script({9, 0});
  CHECK(buf == std::vector<uint8_t>{0x80});
  CHECK(mirror == json::object());
  CHECK(json::from_msgpack(buf) == mirror);
}

// ===== Single-level composites =====

TEST_CASE("encode_one: array containing a single nil")
{
  // Op 8, length 1, then op 0 (nil) for the child.
  // Wire: 0x91 (fixarray, 1) ++ 0xC0 (nil).
  auto [buf, mirror] = run_script({8, 1, 0});
  CHECK(buf == std::vector<uint8_t>{0x91, 0xC0});

  json expected = json::array();
  expected.push_back(nullptr);
  CHECK(mirror == expected);
  CHECK(json::from_msgpack(buf) == mirror);
}

TEST_CASE("encode_one: map with single nil value, 32-char key")
{
  // Op 9, length 1, then 32 bytes for the key, then op 0 (nil) for the
  // value.
  const auto key = canned_key_of_char('a');

  std::vector<uint8_t> script = {9, 1};
  append(script, key.bytes);
  script.push_back(0); // nil value

  auto [buf, mirror] = run_script(script);

  // Expected wire: fixmap(1) ++ str_8(32, key) ++ nil.
  // 32 bytes is > 31 so the encoder uses str_8 (0xD9) not fixstr.
  std::vector<uint8_t> expected_buf = {0x80 | 1};
  expected_buf.push_back(0xD9);
  expected_buf.push_back(static_cast<uint8_t>(gen::KEY_LEN));
  expected_buf.insert(
    expected_buf.end(), key.str.begin(), key.str.end());
  expected_buf.push_back(0xC0);
  CHECK(buf == expected_buf);

  json expected = json::object();
  expected[key.str] = nullptr;
  CHECK(mirror == expected);
  CHECK(json::from_msgpack(buf) == mirror);
}

// ===== Nested composites =====

TEST_CASE("encode_one: array of two empty arrays")
{
  // Op 8, length 2, then op 8, length 0, then op 8, length 0.
  // Wire: 0x92 (fixarray, 2) ++ 0x90 ++ 0x90.
  auto [buf, mirror] = run_script({8, 2, 8, 0, 8, 0});
  CHECK(buf == std::vector<uint8_t>{0x92, 0x90, 0x90});

  json expected = json::array();
  expected.push_back(json::array());
  expected.push_back(json::array());
  CHECK(mirror == expected);
  CHECK(json::from_msgpack(buf) == mirror);
}

TEST_CASE("encode_one: array containing array containing nil")
{
  // [op=8, n=1, op=8, n=1, op=0]
  // Wire: 0x91 0x91 0xC0.
  auto [buf, mirror] = run_script({8, 1, 8, 1, 0});
  CHECK(buf == std::vector<uint8_t>{0x91, 0x91, 0xC0});

  json inner = json::array();
  inner.push_back(nullptr);
  json expected = json::array();
  expected.push_back(inner);
  CHECK(mirror == expected);
  CHECK(json::from_msgpack(buf) == mirror);
}

TEST_CASE("encode_one: object whose value is a singleton array")
{
  // map(1) key={'a' x 32} value=array(1, nil)
  const auto key = canned_key_of_char('a');

  std::vector<uint8_t> script = {9, 1};
  append(script, key.bytes);
  script.push_back(8);
  script.push_back(1);
  script.push_back(0); // nil inside inner array

  auto [buf, mirror] = run_script(script);

  std::vector<uint8_t> expected_buf = {0x80 | 1};
  // str_8(32, "aaaa...")
  expected_buf.push_back(0xD9);
  expected_buf.push_back(static_cast<uint8_t>(gen::KEY_LEN));
  expected_buf.insert(
    expected_buf.end(), key.str.begin(), key.str.end());
  // value: fixarray(1) ++ nil
  expected_buf.push_back(0x91);
  expected_buf.push_back(0xC0);
  CHECK(buf == expected_buf);

  json inner = json::array();
  inner.push_back(nullptr);
  json expected = json::object();
  expected[key.str] = inner;
  CHECK(mirror == expected);
  CHECK(json::from_msgpack(buf) == mirror);
}

TEST_CASE("encode_one: object containing object")
{
  // map(1) outer_key={'a' x 32} value=map(1, inner_key={'b' x 32}, nil)
  const auto outer = canned_key_of_char('a');
  const auto inner = canned_key_of_char('b');

  std::vector<uint8_t> script = {9, 1};
  append(script, outer.bytes);
  script.push_back(9);
  script.push_back(1);
  append(script, inner.bytes);
  script.push_back(0);

  auto [buf, mirror] = run_script(script);

  std::vector<uint8_t> expected_buf = {0x80 | 1};
  // outer key
  expected_buf.push_back(0xD9);
  expected_buf.push_back(static_cast<uint8_t>(gen::KEY_LEN));
  expected_buf.insert(
    expected_buf.end(), outer.str.begin(), outer.str.end());
  // inner map
  expected_buf.push_back(0x80 | 1);
  expected_buf.push_back(0xD9);
  expected_buf.push_back(static_cast<uint8_t>(gen::KEY_LEN));
  expected_buf.insert(
    expected_buf.end(), inner.str.begin(), inner.str.end());
  expected_buf.push_back(0xC0);
  CHECK(buf == expected_buf);

  json inner_obj = json::object();
  inner_obj[inner.str] = nullptr;
  json expected = json::object();
  expected[outer.str] = inner_obj;
  CHECK(mirror == expected);
  CHECK(json::from_msgpack(buf) == mirror);
}

TEST_CASE("encode_one: array mixing object and empty array")
{
  // array(2)
  //   map(1, key='a' x 32, nil)
  //   array(0)
  const auto key = canned_key_of_char('a');

  std::vector<uint8_t> script = {8, 2};
  // child 0: map
  script.push_back(9);
  script.push_back(1);
  append(script, key.bytes);
  script.push_back(0);
  // child 1: empty array
  script.push_back(8);
  script.push_back(0);

  auto [buf, mirror] = run_script(script);

  std::vector<uint8_t> expected_buf = {0x90 | 2};
  // child 0: map
  expected_buf.push_back(0x80 | 1);
  expected_buf.push_back(0xD9);
  expected_buf.push_back(static_cast<uint8_t>(gen::KEY_LEN));
  expected_buf.insert(
    expected_buf.end(), key.str.begin(), key.str.end());
  expected_buf.push_back(0xC0);
  // child 1: empty array
  expected_buf.push_back(0x90);
  CHECK(buf == expected_buf);

  json child0 = json::object();
  child0[key.str] = nullptr;
  json expected = json::array();
  expected.push_back(child0);
  expected.push_back(json::array());
  CHECK(mirror == expected);
  CHECK(json::from_msgpack(buf) == mirror);
}

// ===== Atom branches at top level (smoke tests) =====

TEST_CASE("encode_one: bool true at top level")
{
  // Op 1, then 1 byte (low bit -> true).
  auto [buf, mirror] = run_script({1, 0xFF});
  CHECK(buf == std::vector<uint8_t>{0xC3});
  CHECK(mirror == json(true));
  CHECK(json::from_msgpack(buf) == mirror);
}

TEST_CASE("encode_one: bool false at top level")
{
  // Op 1, then 1 byte (low bit clear -> false).
  auto [buf, mirror] = run_script({1, 0xFE});
  CHECK(buf == std::vector<uint8_t>{0xC2});
  CHECK(mirror == json(false));
  CHECK(json::from_msgpack(buf) == mirror);
}

TEST_CASE("encode_one: uint64 of 7 emits positive fixint")
{
  // Op 2, then 8 bytes for u64 (big-endian per StreamReader::u64).
  // Value 7 fits in positive fixint -> single byte 0x07.
  auto [buf, mirror] = run_script({2, 0, 0, 0, 0, 0, 0, 0, 7});
  CHECK(buf == std::vector<uint8_t>{0x07});
  CHECK(mirror == json(static_cast<uint64_t>(7)));
  CHECK(json::from_msgpack(buf) == mirror);
}

TEST_CASE("encode_one: uint64 of 0xC0 emits uint_8")
{
  // 0xC0 is 192, doesn't fit in positive fixint (max 127), uses uint_8.
  // Wire: 0xCC 0xC0.
  auto [buf, mirror] =
    run_script({2, 0, 0, 0, 0, 0, 0, 0, 0xC0});
  CHECK(buf == std::vector<uint8_t>{0xCC, 0xC0});
  CHECK(mirror == json(static_cast<uint64_t>(0xC0)));
  CHECK(json::from_msgpack(buf) == mirror);
}

TEST_CASE("encode_one: int64 of -1 emits negative fixint")
{
  // Op 3 + u64 = 0xFFFFFFFFFFFFFFFF -> int64_t -1 -> negfixint 0xFF.
  auto [buf, mirror] =
    run_script({3, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
  CHECK(buf == std::vector<uint8_t>{0xFF});
  CHECK(mirror == json(static_cast<int64_t>(-1)));
  CHECK(json::from_msgpack(buf) == mirror);
}
