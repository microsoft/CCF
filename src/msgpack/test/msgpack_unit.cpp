// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "msgpack/encode.h"
#include "msgpack/fluentd_event_time.h"
#include "msgpack/test/format_introspect.h"
#include "msgpack/test/json.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <doctest/doctest.h>
#include <functional>
#include <limits>
#include <nlohmann/json.hpp>
#include <vector>

using namespace ccf::msgpack;
using ccf::msgpack::test::classify_first_byte;
using ccf::msgpack::test::encode_json;
using ccf::msgpack::test::FormatFamily;
using nlohmann::json;

namespace
{
  // Decode a single big-endian integer from buf at offset. Accumulate into
  // uint64_t and narrow at the end so the shift never executes at the result
  // type's width.
  template <typename T>
  T decode_be(const std::vector<uint8_t>& buf, size_t offset)
  {
    static_assert(std::is_unsigned_v<T>);
    uint64_t acc = 0;
    for (size_t i = 0; i < sizeof(T); ++i)
    {
      acc = (acc << 8) | static_cast<uint64_t>(buf[offset + i]);
    }
    return static_cast<T>(acc);
  }
}

// ===== write_uint: smallest-format-wins =====

TEST_CASE("write_uint boundary table")
{
  struct Row
  {
    uint64_t v;
    std::vector<uint8_t> expected;
    FormatFamily family;
  };
  const Row rows[] = {
    {0, {0x00}, FormatFamily::POSITIVE_FIXINT},
    {127, {0x7F}, FormatFamily::POSITIVE_FIXINT},
    {128, {0xCC, 0x80}, FormatFamily::UINT_8},
    {255, {0xCC, 0xFF}, FormatFamily::UINT_8},
    {256, {0xCD, 0x01, 0x00}, FormatFamily::UINT_16},
    {65535, {0xCD, 0xFF, 0xFF}, FormatFamily::UINT_16},
    {65536, {0xCE, 0x00, 0x01, 0x00, 0x00}, FormatFamily::UINT_32},
    {0xFFFFFFFFULL, {0xCE, 0xFF, 0xFF, 0xFF, 0xFF}, FormatFamily::UINT_32},
    {0x100000000ULL,
     {0xCF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
     FormatFamily::UINT_64},
    {std::numeric_limits<uint64_t>::max(),
     {0xCF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
     FormatFamily::UINT_64},
  };
  for (const auto& r : rows)
  {
    CAPTURE(r.v);
    std::vector<uint8_t> buf;
    write_uint(buf, r.v);
    CHECK(buf == r.expected);
    CHECK(classify_first_byte(buf[0]) == r.family);
  }
}

TEST_CASE("tagged writes append after existing bytes")
{
  std::vector<uint8_t> buf = {0xAA, 0xBB};

  write_uint(buf, 0x0102);
  write_array_header(buf, 16);
  write_map_header(buf, 16);

  CHECK(
    buf ==
    std::vector<uint8_t>{
      0xAA, 0xBB, 0xCD, 0x01, 0x02, 0xDC, 0x00, 0x10, 0xDE, 0x00, 0x10});
}

// ===== write_int: smallest-format-wins, non-negative delegates =====

TEST_CASE("write_int delegates to write_uint for non-negative")
{
  std::vector<uint8_t> a;
  std::vector<uint8_t> b;
  write_int(a, 5);
  write_uint(b, 5);
  CHECK(a == b);

  std::vector<uint8_t> c;
  std::vector<uint8_t> d;
  write_int(c, 0);
  write_uint(d, 0);
  CHECK(c == d);

  std::vector<uint8_t> e;
  std::vector<uint8_t> f;
  write_int(e, 1234567);
  write_uint(f, 1234567);
  CHECK(e == f);
}

TEST_CASE("write_int negative boundary table")
{
  struct Row
  {
    int64_t v;
    uint8_t first;
    size_t size;
    FormatFamily family;
  };
  const Row rows[] = {
    {-1, 0xFF, 1, FormatFamily::NEGATIVE_FIXINT},
    {-32, 0xE0, 1, FormatFamily::NEGATIVE_FIXINT},
    {-33, 0xD0, 2, FormatFamily::INT_8},
    {-128, 0xD0, 2, FormatFamily::INT_8},
    {-129, 0xD1, 3, FormatFamily::INT_16},
    {-32768, 0xD1, 3, FormatFamily::INT_16},
    {-32769, 0xD2, 5, FormatFamily::INT_32},
    {std::numeric_limits<int32_t>::min(), 0xD2, 5, FormatFamily::INT_32},
    {static_cast<int64_t>(std::numeric_limits<int32_t>::min()) - 1,
     0xD3,
     9,
     FormatFamily::INT_64},
    {std::numeric_limits<int64_t>::min(), 0xD3, 9, FormatFamily::INT_64},
  };
  for (const auto& r : rows)
  {
    CAPTURE(r.v);
    std::vector<uint8_t> buf;
    write_int(buf, r.v);
    CHECK(buf.size() == r.size);
    CHECK(buf[0] == r.first);
    CHECK(classify_first_byte(buf[0]) == r.family);

    // Decode the payload back to int64_t and check round-trip equality.
    // This catches wrong-width writes (e.g. zero-extending a negative
    // value) and absolute-value bugs that the family + size checks
    // alone miss.
    int64_t decoded = 0;
    switch (r.size)
    {
      case 1:
        // fixint: the byte itself is the int8 bit pattern (negative
        // fixint range is 0xE0..0xFF, which sign-extends correctly).
        decoded = static_cast<int8_t>(buf[0]);
        break;
      case 2:
        decoded = static_cast<int8_t>(buf[1]);
        break;
      case 3:
        decoded = static_cast<int16_t>(decode_be<uint16_t>(buf, 1));
        break;
      case 5:
        decoded = static_cast<int32_t>(decode_be<uint32_t>(buf, 1));
        break;
      case 9:
        decoded = static_cast<int64_t>(decode_be<uint64_t>(buf, 1));
        break;
      default:
        FAIL("unexpected encoded size for write_int row");
    }
    CHECK(decoded == r.v);
  }
}

// ===== write_str =====

TEST_CASE("write_str boundary table")
{
  // Each row exercises both sides of a format-family boundary.
  struct Row
  {
    size_t n;
    uint8_t first;
    size_t header_size;
    FormatFamily family;
  };
  const Row rows[] = {
    {0, 0xA0, 1, FormatFamily::FIXSTR},
    {31, 0xBF, 1, FormatFamily::FIXSTR},
    {32, 0xD9, 2, FormatFamily::STR_8},
    {255, 0xD9, 2, FormatFamily::STR_8},
    {256, 0xDA, 3, FormatFamily::STR_16},
    {65535, 0xDA, 3, FormatFamily::STR_16},
    {65536, 0xDB, 5, FormatFamily::STR_32},
    {70000, 0xDB, 5, FormatFamily::STR_32},
  };
  for (const auto& r : rows)
  {
    CAPTURE(r.n);
    // Position-dependent fill so any payload corruption (bit flip,
    // zeroing, off-by-one) shows up as a byte-compare mismatch.
    std::string s(r.n, '\0');
    for (size_t i = 0; i < r.n; ++i)
    {
      s[i] = static_cast<char>((i * 7 + 13) & 0xFF);
    }
    std::vector<uint8_t> buf;
    write_str(buf, s);
    CHECK(buf.size() == r.header_size + r.n);
    CHECK(buf[0] == r.first);
    CHECK(classify_first_byte(buf[0]) == r.family);
    if (r.n > 0)
    {
      CHECK(std::memcmp(buf.data() + r.header_size, s.data(), r.n) == 0);
    }
  }
}

TEST_CASE("write_str supports payloads stored in the destination buffer")
{
  std::vector<uint8_t> buf = {'t', 'e', 's', 't'};
  buf.shrink_to_fit();
  buf.resize(buf.capacity(), 0xCC);
  auto expected = buf;
  expected.insert(expected.end(), {0xA4, 't', 'e', 's', 't'});
  const std::string_view s{reinterpret_cast<const char*>(buf.data()), 4};

  write_str(buf, s);

  CHECK(buf == expected);
}

TEST_CASE("empty str and bin payloads append to a non-empty buffer")
{
  std::vector<uint8_t> buf = {0xDE, 0xAD};

  write_str(buf, std::string_view{});
  CHECK(buf == std::vector<uint8_t>{0xDE, 0xAD, 0xA0});

  write_bin(buf, std::span<const uint8_t>{});
  CHECK(buf == std::vector<uint8_t>{0xDE, 0xAD, 0xA0, 0xC4, 0x00});
}

// ===== write_bool, write_nil =====

TEST_CASE("write_bool and write_nil produce single byte")
{
  std::vector<uint8_t> buf;
  write_nil(buf);
  CHECK(buf == std::vector<uint8_t>{0xC0});

  buf.clear();
  write_bool(buf, true);
  CHECK(buf == std::vector<uint8_t>{0xC3});

  buf.clear();
  write_bool(buf, false);
  CHECK(buf == std::vector<uint8_t>{0xC2});
}

// ===== write_float =====

// ===== write_bin =====

TEST_CASE("write_bin length prefix and family")
{
  // Boundary table only - generator coverage overlaps with str.
  struct Row
  {
    size_t n;
    uint8_t first;
    size_t header_size;
    FormatFamily family;
  };
  const Row rows[] = {
    {0, 0xC4, 2, FormatFamily::BIN_8},
    {1, 0xC4, 2, FormatFamily::BIN_8},
    {255, 0xC4, 2, FormatFamily::BIN_8},
    {256, 0xC5, 3, FormatFamily::BIN_16},
    {65535, 0xC5, 3, FormatFamily::BIN_16},
    {65536, 0xC6, 5, FormatFamily::BIN_32},
    {70000, 0xC6, 5, FormatFamily::BIN_32},
  };
  for (const auto& r : rows)
  {
    CAPTURE(r.n);
    // Position-dependent fill so any payload corruption (bit flip,
    // zeroing, off-by-one) shows up as a byte-compare mismatch.
    std::vector<uint8_t> data(r.n);
    for (size_t i = 0; i < r.n; ++i)
    {
      data[i] = static_cast<uint8_t>((i * 13 + 7) & 0xFF);
    }
    std::vector<uint8_t> buf;
    write_bin(buf, data);
    CHECK(buf.size() == r.header_size + r.n);
    CHECK(buf[0] == r.first);
    CHECK(classify_first_byte(buf[0]) == r.family);
    if (r.n > 0)
    {
      CHECK(std::memcmp(buf.data() + r.header_size, data.data(), r.n) == 0);
    }
  }
}

TEST_CASE("write_bin supports payloads stored in the destination buffer")
{
  std::vector<uint8_t> buf = {0xDE, 0xAD, 0xBE, 0xEF};
  buf.shrink_to_fit();

  write_bin(buf, std::span<const uint8_t>{buf});

  CHECK(
    buf ==
    std::vector<uint8_t>{
      0xDE, 0xAD, 0xBE, 0xEF, 0xC4, 0x04, 0xDE, 0xAD, 0xBE, 0xEF});
}

TEST_CASE("write_bin does not copy a source below the destination")
{
  std::vector<uint8_t> a(64, 0xAA);
  std::vector<uint8_t> b(64, 0xBB);
  const auto less = std::less<const uint8_t*>{};
  const bool a_first = less(a.data(), b.data());
  auto& low = a_first ? a : b;
  auto& buf = a_first ? b : a;

  auto expected = buf;
  expected.insert(expected.end(), {0xC4, 0x04});
  expected.insert(expected.end(), low.begin(), low.begin() + 4);

  write_bin(buf, std::span<const uint8_t>(low.data(), 4));

  CHECK(buf == expected);
}

// ===== container headers =====

TEST_CASE("write_array_header boundary table")
{
  struct Row
  {
    uint32_t n;
    uint8_t first;
    size_t size;
    FormatFamily family;
  };
  const Row rows[] = {
    {0, 0x90, 1, FormatFamily::FIXARRAY},
    {15, 0x9F, 1, FormatFamily::FIXARRAY},
    {16, 0xDC, 3, FormatFamily::ARRAY_16},
    {65535, 0xDC, 3, FormatFamily::ARRAY_16},
    {65536, 0xDD, 5, FormatFamily::ARRAY_32},
    {std::numeric_limits<uint32_t>::max(), 0xDD, 5, FormatFamily::ARRAY_32},
  };
  for (const auto& r : rows)
  {
    CAPTURE(r.n);
    std::vector<uint8_t> buf;
    write_array_header(buf, r.n);
    CHECK(buf.size() == r.size);
    CHECK(buf[0] == r.first);
    CHECK(classify_first_byte(buf[0]) == r.family);
  }
}

TEST_CASE("write_map_header boundary table")
{
  struct Row
  {
    uint32_t n;
    std::vector<uint8_t> expected;
    FormatFamily family;
  };
  const Row rows[] = {
    {0, {0x80}, FormatFamily::FIXMAP},
    {15, {0x8F}, FormatFamily::FIXMAP},
    {16, {0xDE, 0x00, 0x10}, FormatFamily::MAP_16},
    {65535, {0xDE, 0xFF, 0xFF}, FormatFamily::MAP_16},
    {65536, {0xDF, 0x00, 0x01, 0x00, 0x00}, FormatFamily::MAP_32},
    {std::numeric_limits<uint32_t>::max(),
     {0xDF, 0xFF, 0xFF, 0xFF, 0xFF},
     FormatFamily::MAP_32},
  };
  for (const auto& r : rows)
  {
    CAPTURE(r.n);
    std::vector<uint8_t> buf;
    write_map_header(buf, r.n);
    CHECK(buf == r.expected);
    CHECK(classify_first_byte(buf[0]) == r.family);
    if (r.family == FormatFamily::MAP_16)
    {
      CHECK(decode_be<uint16_t>(buf, 1) == r.n);
    }
    else if (r.family == FormatFamily::MAP_32)
    {
      CHECK(decode_be<uint32_t>(buf, 1) == r.n);
    }
  }
}

// ===== FluentdEventTime: time_point boundary =====
//
// make() takes a system_clock::time_point and rejects:
//   - time_points before the epoch (negative since_epoch),
//   - time_points beyond UINT32_MAX seconds since epoch.
// The valid-input range and rejection boundaries are listed explicitly.

namespace
{
  using time_point = std::chrono::system_clock::time_point;

  // Build a time_point from raw (seconds, nanoseconds) since epoch.
  // Used to pin specific wire-format byte patterns in the byte-shape
  // tests; not the production way to construct a FluentdEventTime.
  time_point tp_from_components(int64_t secs_since_epoch, uint32_t ns_remainder)
  {
    using namespace std::chrono;
    return time_point{seconds{secs_since_epoch} + nanoseconds{ns_remainder}};
  }
}

TEST_CASE("FluentdEventTime::make boundary table")
{
  struct Row
  {
    int64_t seconds;
    uint32_t nanoseconds;
    bool valid;
  };
  const Row rows[] = {
    {-1, 0, false},
    {-1, 999'999'999U, false},
    {0, 0, true},
    {1, 999'999'999U, true},
    {1700000000, 123456789U, true},
    {static_cast<int64_t>(std::numeric_limits<uint32_t>::max()),
     999'999'999U,
     true},
    {static_cast<int64_t>(std::numeric_limits<uint32_t>::max()) + 1, 0, false},
  };

  for (const auto& row : rows)
  {
    CAPTURE(row.seconds);
    CAPTURE(row.nanoseconds);
    bool threw = false;
    try
    {
      const auto et = FluentdEventTime::make(
        tp_from_components(row.seconds, row.nanoseconds));
      CHECK(et.seconds() == static_cast<uint32_t>(row.seconds));
      CHECK(et.nanoseconds() == row.nanoseconds);
    }
    catch (const MsgpackEncodeError& e)
    {
      threw = true;
      CHECK(e.error_code() == Error::INVALID_EVENT_TIME);
    }
    CHECK(threw != row.valid);
  }
}

TEST_CASE("write_fluentd_event_time byte shape")
{
  // Spec (fluentd Forward Protocol v1, EventTime ext type 0, fixext8
  // form): 0xD7 0x00 <s_be4> <ns_be4>.
  // Concrete value chosen so the bytes contain non-trivial bit patterns
  // in every position; any byte-order or layout regression flips at
  // least one of these.
  const auto et =
    FluentdEventTime::make(tp_from_components(0x69F37C9FLL, 0x315B5B4CU));
  std::vector<uint8_t> buf{0xAA, 0xBB};
  write_fluentd_event_time(buf, et);
  const std::vector<uint8_t> expected{
    0xAA, 0xBB, 0xD7, 0x00, 0x69, 0xF3, 0x7C, 0x9F, 0x31, 0x5B, 0x5B, 0x4C};
  CHECK(buf == expected);
}

TEST_CASE("known nested values roundtrip through nlohmann")
{
  const std::vector<json> samples = {
    json::array({1, "two", 3.0, nullptr, true}),
    json::object({{"a", 1}, {"b", "two"}, {"c", json::array({1, 2, 3})}}),
    json::object(
      {{"nested",
        json::array(
          {json::object({{"enabled", true}}), json::binary({0, 1, 255})})}}),
  };
  for (const auto& value : samples)
  {
    std::vector<uint8_t> buf;
    encode_json(buf, value);
    CHECK(json::from_msgpack(buf) == value);
  }
}

TEST_CASE("encode_json handles deeply nested values iteratively")
{
  constexpr size_t DEPTH = 4096;
  json value = nullptr;
  for (size_t i = 0; i < DEPTH; ++i)
  {
    value = json::array({std::move(value)});
  }

  std::vector<uint8_t> buf;
  encode_json(buf, value);

  REQUIRE(buf.size() == DEPTH + 1);
  CHECK(std::all_of(
    buf.begin(), buf.end() - 1, [](uint8_t byte) { return byte == 0x91; }));
  CHECK(buf.back() == 0xC0);
}

TEST_CASE("FluentdEventTime roundtrips through nlohmann")
{
  const auto event_time =
    FluentdEventTime::make(tp_from_components(1700000000LL, 123456789U));
  std::vector<uint8_t> buf;
  write_fluentd_event_time(buf, event_time);

  const auto decoded = json::from_msgpack(buf);
  REQUIRE(decoded.is_binary());
  const auto& binary = decoded.get_binary();
  CHECK(binary.has_subtype());
  CHECK(binary.subtype() == 0);
  REQUIRE(binary.size() == 8);

  const uint32_t seconds = (uint32_t(binary[0]) << 24) |
    (uint32_t(binary[1]) << 16) | (uint32_t(binary[2]) << 8) |
    uint32_t(binary[3]);
  const uint32_t nanoseconds = (uint32_t(binary[4]) << 24) |
    (uint32_t(binary[5]) << 16) | (uint32_t(binary[6]) << 8) |
    uint32_t(binary[7]);
  CHECK(seconds == event_time.seconds());
  CHECK(nanoseconds == event_time.nanoseconds());
}

TEST_CASE("fluentd Message-mode byte-for-byte vector")
{
  const std::vector<uint8_t> expected = {
    0x93, 0xAC, 0x6D, 0x79, 0x61, 0x70, 0x70, 0x2E, 0x61, 0x63, 0x63,
    0x65, 0x73, 0x73, 0xD7, 0x00, 0x69, 0xF3, 0x7C, 0x9F, 0x31, 0x5B,
    0x5B, 0x4C, 0x83, 0xA4, 0x70, 0x61, 0x74, 0x68, 0xAB, 0x2F, 0x61,
    0x70, 0x69, 0x2F, 0x76, 0x31, 0x2F, 0x66, 0x6F, 0x6F, 0xA6, 0x73,
    0x74, 0x61, 0x74, 0x75, 0x73, 0xCC, 0xC8, 0xA2, 0x6D, 0x73, 0xCB,
    0x40, 0x28, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9A};

  std::vector<uint8_t> buf;
  write_array_header(buf, 3);
  write_str(buf, "myapp.access");
  write_fluentd_event_time(
    buf, FluentdEventTime::make(tp_from_components(0x69F37C9FLL, 0x315B5B4CU)));
  write_map_header(buf, 3);
  write_str(buf, "path");
  write_str(buf, "/api/v1/foo");
  write_str(buf, "status");
  write_uint(buf, 200);
  write_str(buf, "ms");
  write_float(buf, 12.3);

  CHECK(buf == expected);
}

// ===== write_float: non-finite bit-patterns pass through =====

TEST_CASE("write_float passes through non-finite bit-patterns unchanged")
{
  // The encoder doc states NaN / +/-inf / signalling-NaN are emitted
  // verbatim with no canonicalisation. Round-trip the bit pattern
  // through encode and back-decode; bytes 1..9 must equal the input
  // bits exactly.
  struct Row
  {
    uint64_t bits;
    const char* label;
  };
  const Row rows[] = {
    {0x7FF8000000000000ULL, "quiet NaN"},
    {0x7FF0000000000001ULL, "signalling NaN"},
    {0x7FF0000000000000ULL, "+inf"},
    {0xFFF0000000000000ULL, "-inf"},
    {0x8000000000000000ULL, "negative zero"},
    {0x0000000000000000ULL, "positive zero"},
  };
  for (const auto& r : rows)
  {
    CAPTURE(r.label);
    double v;
    std::memcpy(&v, &r.bits, sizeof(v));
    std::vector<uint8_t> buf;
    write_float(buf, v);
    REQUIRE(buf.size() == 9);
    CHECK(buf[0] == 0xCB);
    CHECK(decode_be<uint64_t>(buf, 1) == r.bits);
  }
}

// ===== to_string(Error) =====

TEST_CASE("to_string(Error) maps every enumerator to a unique stable label")
{
  // Each enum value must produce its own non-empty label; a swap or
  // typo in the switch would collapse two distinct codes to the same
  // string and would be caught here.
  const Error all[] = {
    Error::STRING_TOO_LARGE,
    Error::BIN_TOO_LARGE,
    Error::INVALID_EVENT_TIME,
  };
  std::vector<std::string_view> seen;
  for (const auto e : all)
  {
    const auto s = to_string(e);
    CHECK_FALSE(s.empty());
    for (const auto& prev : seen)
    {
      CHECK(prev != s);
    }
    seen.push_back(s);
  }

  // Spot-check a couple of specific labels so a future rename of an
  // enumerator name in the switch is caught here too.
  CHECK(to_string(Error::STRING_TOO_LARGE) == "STRING_TOO_LARGE");
  CHECK(to_string(Error::INVALID_EVENT_TIME) == "INVALID_EVENT_TIME");
}
