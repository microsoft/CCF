// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
//
// Differential test: encode with ccf::msgpack, decode with
// nlohmann::json::from_msgpack, assert structural equality.
// nlohmann is the oracle.
#include "msgpack/encode.h"

#include "msgpack/test/gen.h"

#include <chrono>
#include <cstdint>
#include <doctest/doctest.h>
#include <limits>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

using namespace ccf::msgpack;
using nlohmann::json;
namespace gen = ccf::msgpack::test::gen;

namespace
{
  // Build a system_clock::time_point from raw (seconds, nanoseconds)
  // since epoch. Used to pin wire-format byte patterns; not how
  // production code constructs a FluentdEventTime.
  std::chrono::system_clock::time_point tp_from_components(
    int64_t secs_since_epoch, uint32_t ns_remainder)
  {
    using namespace std::chrono;
    return system_clock::time_point{
      seconds{secs_since_epoch} + nanoseconds{ns_remainder}};
  }
  // Recursive: encode a nlohmann::json value using our writers, then
  // expect from_msgpack to reproduce it. Caller-driven mapping rather
  // than walking the json type from inside the encoder.
  void encode_json(std::vector<uint8_t>& buf, const json& v)
  {
    if (v.is_null())
    {
      write_nil(buf);
    }
    else if (v.is_boolean())
    {
      write_bool(buf, v.get<bool>());
    }
    else if (v.is_number_unsigned())
    {
      write_uint(buf, v.get<uint64_t>());
    }
    else if (v.is_number_integer())
    {
      write_int(buf, v.get<int64_t>());
    }
    else if (v.is_number_float())
    {
      write_float(buf, v.get<double>());
    }
    else if (v.is_string())
    {
      write_str(buf, v.get_ref<const std::string&>());
    }
    else if (v.is_array())
    {
      write_array_header(buf, static_cast<uint32_t>(v.size()));
      for (const auto& e : v)
      {
        encode_json(buf, e);
      }
    }
    else if (v.is_object())
    {
      write_map_header(buf, static_cast<uint32_t>(v.size()));
      for (const auto& [k, val] : v.items())
      {
        write_str(buf, k);
        encode_json(buf, val);
      }
    }
    else
    {
      FAIL("unsupported json type for differential test");
    }
  }

  json gen_scalar(gen::Rng& rng, int branch)
  {
    switch (branch)
    {
      case 0:
        return nullptr;
      case 1:
        return gen::boolean()(rng);
      case 2:
        return gen::uint64_in_range(0, std::numeric_limits<uint64_t>::max())(rng);
      case 3:
        return gen::int64_in_range(std::numeric_limits<int64_t>::min(), -1)(rng);
      case 4:
        return gen::finite_double()(rng);
      case 5:
        return gen::ascii_string_of_size(
          gen::size_biased(40, {0, 31, 32, 256}))(rng);
      default:
        return nullptr;
    }
  }

  // Recursive value generator: scalars at depth 0, plus arrays/maps at
  // higher depth. Bounded depth keeps iteration fast.
  json gen_value(gen::Rng& rng, int depth)
  {
    std::uniform_int_distribution<int> branch_d(
      0, depth > 0 ? 7 : 5); // 6,7 add array/map only at depth > 0
    int b = branch_d(rng);
    if (b <= 5)
    {
      return gen_scalar(rng, b);
    }
    std::uniform_int_distribution<size_t> size_d(0, 4);
    const auto n = size_d(rng);
    if (b == 6)
    {
      json arr = json::array();
      for (size_t i = 0; i < n; ++i)
      {
        arr.push_back(gen_value(rng, depth - 1));
      }
      return arr;
    }
    json obj = json::object();
    for (size_t i = 0; i < n; ++i)
    {
      // Object keys: short string of size <= 10. Duplicate keys are
      // collapsed by nlohmann::json's object representation; we encode
      // .size() pairs (the deduplicated count), so the count claimed
      // by our map header always matches the count produced.
      const auto key = gen::ascii_string_of_size(gen::size_in_range(1, 10))(rng);
      obj[key] = gen_value(rng, depth - 1);
    }
    return obj;
  }
}

TEST_CASE("differential: encode then nlohmann::from_msgpack roundtrip")
{
  gen::Rng rng(0x0DDDD1FF);
  INFO("seed=0x0DDDD1FF");

  for (int i = 0; i < 100; ++i)
  {
    json v = gen_value(rng, 3); // depth up to 3 covers nesting
    CAPTURE(v.dump());
    std::vector<uint8_t> buf;
    encode_json(buf, v);
    json decoded = json::from_msgpack(buf);
    CHECK(decoded == v);
  }
}

TEST_CASE("differential: scalar coverage")
{
  // Hand-picked values that exercise specific format families.
  const std::vector<json> samples = {
    nullptr,
    true,
    false,
    0,
    127,
    128,
    255,
    256,
    65535,
    65536,
    static_cast<uint64_t>(0xFFFFFFFFULL),
    static_cast<uint64_t>(0x100000000ULL),
    -1,
    -32,
    -33,
    -128,
    -32768,
    -32769,
    1.5,
    -1.5,
    0.0,
    "",
    "x",
    std::string(31, 'a'),
    std::string(32, 'b'),
    std::string(256, 'c'),
    json::array({1, "two", 3.0, nullptr, true}),
    json::object({{"a", 1}, {"b", "two"}, {"c", json::array({1, 2, 3})}}),
  };
  for (const auto& v : samples)
  {
    CAPTURE(v.dump());
    std::vector<uint8_t> buf;
    encode_json(buf, v);
    json decoded = json::from_msgpack(buf);
    CHECK(decoded == v);
  }
}

TEST_CASE("differential: FluentdEventTime decodes as binary_t with subtype 0")
{
  const auto et = FluentdEventTime::make(
    tp_from_components(1700000000LL, 123456789U));
  std::vector<uint8_t> buf;
  write_event_time(buf, et);

  json decoded = json::from_msgpack(buf);
  REQUIRE(decoded.is_binary());
  const auto& bin = decoded.get_binary();
  CHECK(bin.has_subtype());
  CHECK(bin.subtype() == 0);
  REQUIRE(bin.size() == 8);
  // bytes[0..4) = seconds_be, bytes[4..8) = nanoseconds_be
  uint32_t s = (uint32_t(bin[0]) << 24) | (uint32_t(bin[1]) << 16) |
    (uint32_t(bin[2]) << 8) | uint32_t(bin[3]);
  uint32_t ns = (uint32_t(bin[4]) << 24) | (uint32_t(bin[5]) << 16) |
    (uint32_t(bin[6]) << 8) | uint32_t(bin[7]);
  CHECK(s == et.seconds());
  CHECK(ns == et.nanoseconds());
}

TEST_CASE("fluentd Message-mode byte-for-byte vector")
{
  // A complete fluentd in_forward Message-mode payload, hand-assembled
  // from the spec (Forward Protocol v1: Message = [tag, time, record]).
  // Pinning the exact wire bytes catches any regression in
  // format-family selection, length prefixing, or EventTime layout.
  //
  // Decoded structure:
  //   ['myapp.access',
  //    FluentdEventTime(seconds=0x69F37C9F, nanoseconds=0x315B5B4C),
  //    {'path': '/api/v1/foo', 'status': 200, 'ms': 12.3}]
  const std::vector<uint8_t> expected = {
    0x93, 0xAC, 0x6D, 0x79, 0x61, 0x70, 0x70, 0x2E, 0x61, 0x63, 0x63, 0x65,
    0x73, 0x73, 0xD7, 0x00, 0x69, 0xF3, 0x7C, 0x9F, 0x31, 0x5B, 0x5B, 0x4C,
    0x83, 0xA4, 0x70, 0x61, 0x74, 0x68, 0xAB, 0x2F, 0x61, 0x70, 0x69, 0x2F,
    0x76, 0x31, 0x2F, 0x66, 0x6F, 0x6F, 0xA6, 0x73, 0x74, 0x61, 0x74, 0x75,
    0x73, 0xCC, 0xC8, 0xA2, 0x6D, 0x73, 0xCB, 0x40, 0x28, 0x99, 0x99, 0x99,
    0x99, 0x99, 0x9A};

  std::vector<uint8_t> buf;
  write_array_header(buf, 3);
  write_str(buf, "myapp.access");
  write_event_time(
    buf,
    FluentdEventTime::make(tp_from_components(0x69F37C9FLL, 0x315B5B4CU)));
  write_map_header(buf, 3);
  write_str(buf, "path");
  write_str(buf, "/api/v1/foo");
  write_str(buf, "status");
  write_uint(buf, 200);
  write_str(buf, "ms");
  write_float(buf, 12.3);

  CHECK(buf == expected);
}

TEST_CASE("differential: 16-element array crosses fixarray->array16 boundary")
{
  // fixarray covers [0, 15]; 16 elements forces array_16. Confirm the
  // wider header round-trips correctly through the oracle.
  json arr = json::array();
  for (int i = 0; i < 16; ++i)
  {
    arr.push_back(i);
  }
  std::vector<uint8_t> buf;
  encode_json(buf, arr);
  REQUIRE(buf.size() >= 3);
  CHECK(buf[0] == 0xDC); // array_16
  CHECK(buf[1] == 0x00);
  CHECK(buf[2] == 0x10);
  json decoded = json::from_msgpack(buf);
  CHECK(decoded == arr);
}
