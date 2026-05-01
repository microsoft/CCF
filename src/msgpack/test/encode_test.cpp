// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "msgpack/encode.h"

#include "msgpack/test/format_introspect.h"
#include "msgpack/test/gen.h"

#include <cmath>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <doctest/doctest.h>
#include <limits>
#include <vector>

using namespace ccf::msgpack;
using ccf::msgpack::test::classify_first_byte;
using ccf::msgpack::test::FormatFamily;
namespace gen = ccf::msgpack::test::gen;

namespace
{
  constexpr int property_iters = 200;

  // Decode a single big-endian integer from buf at offset (helper for
  // length-prefix property tests). Accumulate into uint64_t and narrow
  // at the end so the shift never executes at the result type's width
  // (avoids any reliance on integer-promotion subtleties).
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

TEST_CASE("write_uint smallest-format-wins (property)")
{
  gen::Rng rng(0xCAFE);
  INFO("seed=0xCAFE");

  // Bias: small values exercise positive fixint and uint8/16; boundary
  // crossings exercise the wider widths.
  auto value_gen = gen::one_of<uint64_t>({
    gen::uint64_in_range(0, 127),
    gen::uint64_in_range(128, 255),
    gen::uint64_in_range(256, 65535),
    gen::uint64_in_range(65536, 0xFFFFFFFFULL),
    gen::uint64_in_range(0x100000000ULL, std::numeric_limits<uint64_t>::max()),
  });

  for (int i = 0; i < property_iters; ++i)
  {
    const auto v = value_gen(rng);
    std::vector<uint8_t> buf;
    write_uint(buf, v);
    REQUIRE_FALSE(buf.empty());

    const auto family = classify_first_byte(buf[0]);

    if (v <= 0x7FU)
    {
      CHECK(family == FormatFamily::POSITIVE_FIXINT);
      CHECK(buf.size() == 1);
      CHECK(buf[0] == v);
    }
    else if (v <= 0xFFU)
    {
      CHECK(family == FormatFamily::UINT_8);
      CHECK(buf.size() == 2);
      CHECK(buf[1] == v);
    }
    else if (v <= 0xFFFFU)
    {
      CHECK(family == FormatFamily::UINT_16);
      CHECK(buf.size() == 3);
      CHECK(decode_be<uint16_t>(buf, 1) == v);
    }
    else if (v <= 0xFFFFFFFFULL)
    {
      CHECK(family == FormatFamily::UINT_32);
      CHECK(buf.size() == 5);
      CHECK(decode_be<uint32_t>(buf, 1) == v);
    }
    else
    {
      CHECK(family == FormatFamily::UINT_64);
      CHECK(buf.size() == 9);
      CHECK(decode_be<uint64_t>(buf, 1) == v);
    }
  }
}

TEST_CASE("write_uint boundary table")
{
  // Each row: input value, expected first byte, expected total size.
  struct Row
  {
    uint64_t v;
    uint8_t first;
    size_t size;
    FormatFamily family;
  };
  const Row rows[] = {
    {0, 0x00, 1, FormatFamily::POSITIVE_FIXINT},
    {127, 0x7F, 1, FormatFamily::POSITIVE_FIXINT},
    {128, 0xCC, 2, FormatFamily::UINT_8},
    {255, 0xCC, 2, FormatFamily::UINT_8},
    {256, 0xCD, 3, FormatFamily::UINT_16},
    {65535, 0xCD, 3, FormatFamily::UINT_16},
    {65536, 0xCE, 5, FormatFamily::UINT_32},
    {0xFFFFFFFFULL, 0xCE, 5, FormatFamily::UINT_32},
    {0x100000000ULL, 0xCF, 9, FormatFamily::UINT_64},
    {std::numeric_limits<uint64_t>::max(), 0xCF, 9, FormatFamily::UINT_64},
  };
  for (const auto& r : rows)
  {
    CAPTURE(r.v);
    std::vector<uint8_t> buf;
    write_uint(buf, r.v);
    CHECK(buf.size() == r.size);
    CHECK(buf[0] == r.first);
    CHECK(classify_first_byte(buf[0]) == r.family);
  }
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
        decoded =
          static_cast<int16_t>(decode_be<uint16_t>(buf, 1));
        break;
      case 5:
        decoded =
          static_cast<int32_t>(decode_be<uint32_t>(buf, 1));
        break;
      case 9:
        decoded =
          static_cast<int64_t>(decode_be<uint64_t>(buf, 1));
        break;
      default:
        FAIL("unexpected encoded size for write_int row");
    }
    CHECK(decoded == r.v);
  }
}

TEST_CASE("write_int smallest-format-wins (property)")
{
  // Mirror of the write_uint property test for negative values.
  // Every iteration: emit, classify, and verify the back-decoded
  // payload equals the original value. The payload check distinguishes
  // a wrong-width or absolute-value bug (which the family check alone
  // would miss) from correct output.
  gen::Rng rng(0x511EE);
  INFO("seed=0x511EE");

  auto value_gen = gen::one_of<int64_t>({
    gen::int64_in_range(-32, -1),
    gen::int64_in_range(-128, -33),
    gen::int64_in_range(-32768, -129),
    gen::int64_in_range(
      std::numeric_limits<int32_t>::min(), -32769),
    gen::int64_in_range(
      std::numeric_limits<int64_t>::min(),
      static_cast<int64_t>(std::numeric_limits<int32_t>::min()) - 1),
  });

  for (int i = 0; i < property_iters; ++i)
  {
    const auto v = value_gen(rng);
    CAPTURE(v);
    std::vector<uint8_t> buf;
    write_int(buf, v);
    REQUIRE_FALSE(buf.empty());

    const auto family = classify_first_byte(buf[0]);

    if (v >= -32)
    {
      CHECK(family == FormatFamily::NEGATIVE_FIXINT);
      CHECK(buf.size() == 1);
      CHECK(
        static_cast<int8_t>(buf[0]) == static_cast<int8_t>(v));
    }
    else if (v >= std::numeric_limits<int8_t>::min())
    {
      CHECK(family == FormatFamily::INT_8);
      CHECK(buf.size() == 2);
      CHECK(static_cast<int8_t>(buf[1]) == static_cast<int8_t>(v));
    }
    else if (v >= std::numeric_limits<int16_t>::min())
    {
      CHECK(family == FormatFamily::INT_16);
      CHECK(buf.size() == 3);
      const auto raw = decode_be<uint16_t>(buf, 1);
      CHECK(static_cast<int16_t>(raw) == static_cast<int16_t>(v));
    }
    else if (v >= std::numeric_limits<int32_t>::min())
    {
      CHECK(family == FormatFamily::INT_32);
      CHECK(buf.size() == 5);
      const auto raw = decode_be<uint32_t>(buf, 1);
      CHECK(static_cast<int32_t>(raw) == static_cast<int32_t>(v));
    }
    else
    {
      CHECK(family == FormatFamily::INT_64);
      CHECK(buf.size() == 9);
      const auto raw = decode_be<uint64_t>(buf, 1);
      CHECK(static_cast<int64_t>(raw) == v);
    }
  }
}

// ===== write_str =====

TEST_CASE("write_str length prefix and family (property)")
{
  gen::Rng rng(0xBEEF);
  INFO("seed=0xBEEF");

  // Sizes biased toward small with explicit boundary picks.
  auto size_gen =
    gen::size_biased(40, {0, 31, 32, 255, 256, 65535, 65536, 70000});
  auto str_gen = gen::string_of_size(size_gen);

  for (int i = 0; i < property_iters; ++i)
  {
    const auto s = str_gen(rng);
    const auto n = s.size();
    std::vector<uint8_t> buf;
    write_str(buf, s);

    const auto family = classify_first_byte(buf[0]);

    if (n <= 31)
    {
      CHECK(family == FormatFamily::FIXSTR);
      CHECK(buf.size() == 1 + n);
      CHECK((buf[0] & 0x1FU) == n);
    }
    else if (n <= 0xFF)
    {
      CHECK(family == FormatFamily::STR_8);
      CHECK(buf.size() == 2 + n);
      CHECK(buf[1] == n);
    }
    else if (n <= 0xFFFF)
    {
      CHECK(family == FormatFamily::STR_16);
      CHECK(buf.size() == 3 + n);
      CHECK(decode_be<uint16_t>(buf, 1) == n);
    }
    else
    {
      CHECK(family == FormatFamily::STR_32);
      CHECK(buf.size() == 5 + n);
      CHECK(decode_be<uint32_t>(buf, 1) == n);
    }

    // Payload bytes match input.
    const auto payload_offset = buf.size() - n;
    CHECK(std::memcmp(buf.data() + payload_offset, s.data(), n) == 0);
  }
}

TEST_CASE("write_str boundary table")
{
  // Deterministic boundary coverage to complement the probabilistic
  // size_biased property test above. Each row exercises both sides of
  // a format-family boundary.
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

TEST_CASE("write_float always emits float64")
{
  gen::Rng rng(0xF10A7);
  INFO("seed=0xF10A7");
  auto g = gen::finite_double();
  for (int i = 0; i < property_iters; ++i)
  {
    const auto v = g(rng);
    std::vector<uint8_t> buf;
    write_float(buf, v);
    REQUIRE(buf.size() == 9);
    CHECK(buf[0] == 0xCB);
    // Reconstruct the IEEE-754 bits and confirm equality (no narrowing).
    uint64_t bits = decode_be<uint64_t>(buf, 1);
    double back;
    std::memcpy(&back, &bits, sizeof(back));
    if (std::isnan(v))
    {
      CHECK(std::isnan(back));
    }
    else
    {
      CHECK(back == v);
    }
  }
}

// ===== write_bin =====

TEST_CASE("write_bin length prefix and family")
{
  // Boundary table only — generator coverage overlaps with str.
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

TEST_CASE("write_map_header boundary table and overflow throws")
{
  struct Row
  {
    uint32_t n;
    uint8_t first;
    size_t size;
    FormatFamily family;
  };
  const Row rows[] = {
    {0, 0x80, 1, FormatFamily::FIXMAP},
    {15, 0x8F, 1, FormatFamily::FIXMAP},
    {16, 0xDE, 3, FormatFamily::MAP_16},
    {65535, 0xDE, 3, FormatFamily::MAP_16},
  };
  for (const auto& r : rows)
  {
    CAPTURE(r.n);
    std::vector<uint8_t> buf;
    write_map_header(buf, r.n);
    CHECK(buf.size() == r.size);
    CHECK(buf[0] == r.first);
    CHECK(classify_first_byte(buf[0]) == r.family);
  }

  std::vector<uint8_t> buf;
  try
  {
    write_map_header(buf, 65536);
    FAIL("expected MsgpackEncodeError");
  }
  catch (const MsgpackEncodeError& e)
  {
    CHECK(e.error_code() == Error::MAP_TOO_LARGE);
  }
}

// ===== FluentdEventTime: time_point boundary =====
//
// make() takes a system_clock::time_point and rejects:
//   - time_points before the epoch (negative since_epoch),
//   - time_points beyond UINT32_MAX seconds since epoch.
// The valid-input range and the rejection boundary are exercised
// together as a single mixed property.

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

TEST_CASE("FluentdEventTime::make accepts iff seconds-since-epoch in [0, UINT32_MAX]")
{
  gen::Rng rng(0xE7E7);
  INFO("seed=0xE7E7");

  // Boundary seconds values: just-below-zero, zero, just-above-zero,
  // mid-range, just-below-UINT32_MAX, exactly UINT32_MAX, and one
  // past. 30% of draws hit a boundary; 70% are uniform across a
  // wider int64 range that straddles the valid window.
  const int64_t s_boundaries[] = {
    -1,
    0,
    1,
    1700000000,
    static_cast<int64_t>(std::numeric_limits<uint32_t>::max()) - 1,
    static_cast<int64_t>(std::numeric_limits<uint32_t>::max()),
    static_cast<int64_t>(std::numeric_limits<uint32_t>::max()) + 1,
  };
  std::uniform_int_distribution<int> coin(0, 99);
  std::uniform_int_distribution<size_t> bp(0, std::size(s_boundaries) - 1);
  std::uniform_int_distribution<int64_t> any_s(
    -1'000'000LL,
    static_cast<int64_t>(std::numeric_limits<uint32_t>::max()) + 1'000'000LL);
  std::uniform_int_distribution<uint32_t> any_ns(0, 999'999'999U);

  for (int i = 0; i < property_iters; ++i)
  {
    const int64_t s_raw =
      (coin(rng) < 30) ? s_boundaries[bp(rng)] : any_s(rng);
    const uint32_t ns = any_ns(rng);
    CAPTURE(s_raw);
    CAPTURE(ns);

    const auto tp = tp_from_components(s_raw, ns);

    const bool should_throw =
      s_raw < 0 ||
      s_raw > static_cast<int64_t>(std::numeric_limits<uint32_t>::max());
    bool threw = false;
    try
    {
      const auto et = FluentdEventTime::make(tp);
      CHECK(et.seconds() == static_cast<uint32_t>(s_raw));
      CHECK(et.nanoseconds() == ns);
    }
    catch (const MsgpackEncodeError& e)
    {
      threw = true;
      CHECK(e.error_code() == Error::INVALID_EVENT_TIME);
    }
    CHECK(threw == should_throw);
  }
}

TEST_CASE("write_event_time byte shape")
{
  // Spec (fluentd Forward Protocol v1, EventTime ext type 0, fixext8
  // form): 0xD7 0x00 <s_be4> <ns_be4>.
  // Concrete value chosen so the bytes contain non-trivial bit patterns
  // in every position; any byte-order or layout regression flips at
  // least one of these.
  const auto et = FluentdEventTime::make(
    tp_from_components(0x69F37C9FLL, 0x315B5B4CU));
  std::vector<uint8_t> buf;
  write_event_time(buf, et);
  const std::vector<uint8_t> expected{
    0xD7, 0x00, 0x69, 0xF3, 0x7C, 0x9F, 0x31, 0x5B, 0x5B, 0x4C};
  CHECK(buf == expected);
}

TEST_CASE("write_event_time always fixext8 (property)")
{
  gen::Rng rng(0x517E);
  INFO("seed=0x517E");
  std::uniform_int_distribution<int64_t> sd(
    0, static_cast<int64_t>(std::numeric_limits<uint32_t>::max()));
  std::uniform_int_distribution<uint32_t> nd(0, 999'999'999U);
  for (int i = 0; i < property_iters; ++i)
  {
    const auto s = sd(rng);
    const auto ns = nd(rng);
    const auto et = FluentdEventTime::make(tp_from_components(s, ns));
    std::vector<uint8_t> buf;
    write_event_time(buf, et);
    REQUIRE(buf.size() == 10);
    CHECK(buf[0] == 0xD7);
    CHECK(buf[1] == 0x00);
    CHECK(decode_be<uint32_t>(buf, 2) == et.seconds());
    CHECK(decode_be<uint32_t>(buf, 6) == et.nanoseconds());
  }
}

// ===== write_float: non-finite bit-patterns pass through =====

TEST_CASE("write_float passes through non-finite bit-patterns unchanged")
{
  // The encoder doc states NaN / ±inf / signalling-NaN are emitted
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
    Error::MAP_TOO_LARGE,
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

