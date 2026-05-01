// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Header-only msgpack encoder.
//
// Spec: https://github.com/msgpack/msgpack/blob/master/spec.md
//
// Encoder-only. Decoding is out of scope; CCF currently decodes via
// nlohmann::json::from_msgpack. The encoder writes the smallest format
// family that fits each value (the spec's recommended canonical form).
//
// Supported subset:
//   - All msgpack scalar types (nil, bool, int, uint, float64,
//     str fixstr/str8/str16/str32, bin bin8/16/32).
//   - Arrays (fixarray/array16/array32) and maps (fixmap/map16).
//   - The fluentd in_forward EventTime ext type (ext type 0, fixext8 form).
// Out of scope:
//   - map32 (write_map_header throws MAP_TOO_LARGE for n > 65535).
//   - float32 (write_float always emits float64).
//   - The 12-byte EventTime ext form (fixext8 covers all uint32 seconds).
//
// Failure modes that may escape ANY write_* function:
//   - MsgpackEncodeError on encoder-defined limits (see Error enum).
//   - std::bad_alloc from the underlying std::vector if buffer growth
//     fails. The encoder offers no special handling — callers that
//     might recover from OOM should treat the buffer as undefined-but-
//     well-typed.

#include "msgpack/endian.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace ccf::msgpack
{
  // ===== Errors as data, throw at the boundary =====

  enum class Error : uint8_t
  {
    STRING_TOO_LARGE = 1, // > 2^32-1 bytes
    BIN_TOO_LARGE = 2, // > 2^32-1 bytes
    MAP_TOO_LARGE = 3, // > 65535 elements (we cap at map16)
    INVALID_EVENT_TIME = 4, // nanoseconds >= 1_000_000_000
  };

  // Every error knows how to describe itself. The returned string_view
  // refers to a function-local string literal (static storage duration);
  // it is safe to retain indefinitely.
  //
  // Tests should match on MsgpackEncodeError::error_code(), not what():
  // what() messages are not part of the API contract and may be
  // reformatted at any time.
  [[nodiscard]] inline std::string_view to_string(Error e)
  {
    switch (e)
    {
      case Error::STRING_TOO_LARGE:
        return "STRING_TOO_LARGE";
      case Error::BIN_TOO_LARGE:
        return "BIN_TOO_LARGE";
      case Error::MAP_TOO_LARGE:
        return "MAP_TOO_LARGE";
      case Error::INVALID_EVENT_TIME:
        return "INVALID_EVENT_TIME";
      default:
        return "UNKNOWN_MSGPACK_ERROR";
    }
  }

  // Thrown by encoder boundary functions (write_*, FluentdEventTime::make).
  //
  // API contract:
  //   - error_code() identifies the failure as a stable enum value.
  //   - what() returns a human-readable diagnostic that includes the
  //     offending value where applicable. The exact format is NOT
  //     part of the API; do not parse it. Tests asserting on a
  //     specific failure mode must match on error_code().
  class MsgpackEncodeError : public std::runtime_error
  {
  public:
    explicit MsgpackEncodeError(Error err, const std::string& what) :
      std::runtime_error(what),
      error(err)
    {}

    // Convenience constructor: composes the standard "<NAME>: <detail>"
    // shape used at every throw site, ensuring every diagnostic
    // includes the error code's name without each call site having to
    // remember the convention.
    [[nodiscard]] static MsgpackEncodeError make(Error err, std::string_view detail)
    {
      return MsgpackEncodeError(
        err, std::string{to_string(err)} + ": " + std::string{detail});
    }

    [[nodiscard]] Error error_code() const
    {
      return error;
    }

  private:
    Error error;
  };

  // ===== FluentdEventTime: validated wrapper for fluentd's ext type 0 =====
  //
  // This is fluentd's application-defined timestamp ext type, NOT the
  // msgpack-spec Timestamp (ext type -1). The two have different
  // layouts. If you need msgpack-spec Timestamp later, add it as a
  // separate type (TimestampExt or similar) — do not overload this one.
  //
  // Wire format (fixext8): 0xD7 0x00 <seconds_be4> <nanoseconds_be4>.
  //
  // Construction takes a system_clock::time_point so the caller can't
  // accidentally swap the seconds and nanoseconds operands (the unit
  // types are distinct), and so callers that already work in
  // time_point don't have to decompose by hand.
  //
  // Range limitations enforced by make():
  //   - seconds-since-epoch must fit in uint32_t (range ends at
  //     2106-02-07 06:28:15 UTC); a time_point outside this range
  //     throws INVALID_EVENT_TIME rather than silently wrapping.
  //   - the time_point must not predate the epoch (negative
  //     seconds-since-epoch); these throw INVALID_EVENT_TIME.
  // If timestamps past 2106 are ever needed, switch to the msgpack-spec
  // Timestamp 64 form (34-bit seconds, range to year 2514) as a
  // sibling type.

  class FluentdEventTime
  {
  public:
    // Throws MsgpackEncodeError(INVALID_EVENT_TIME) if the time_point
    // is before the epoch or beyond 2106-02-07 06:28:15 UTC.
    // The thrown what() includes the offending epoch-seconds value.
    //
    // Precision: the wire format carries 32-bit nanoseconds. On
    // platforms where system_clock::period is at least as fine as
    // nanoseconds (libstdc++: 1ns; MSVC STL: 100ns), the full
    // sub-second component round-trips. On platforms where it is
    // coarser (libc++: 1μs), the low digits of the encoded
    // nanoseconds field are always zero — still spec-conformant,
    // just no precision beyond the platform's clock resolution.
    [[nodiscard]] static FluentdEventTime make(
      std::chrono::system_clock::time_point tp)
    {
      const auto since_epoch = tp.time_since_epoch();

      // Reject any time_point that predates the epoch. We must check
      // the original duration here (not secs.count() below): for a
      // small negative duration like -0.5s, duration_cast<seconds>
      // truncates toward zero and yields 0, masking the negativity.
      if (since_epoch < std::chrono::system_clock::duration::zero())
      {
        const auto ns_signed =
          std::chrono::duration_cast<std::chrono::nanoseconds>(since_epoch)
            .count();
        throw MsgpackEncodeError::make(
          Error::INVALID_EVENT_TIME,
          "time_point predates the epoch (since_epoch_ns=" +
            std::to_string(ns_signed) + ")");
      }

      const auto secs =
        std::chrono::duration_cast<std::chrono::seconds>(since_epoch);
      const auto secs_count = secs.count();
      if (secs_count >
          static_cast<int64_t>(std::numeric_limits<uint32_t>::max()))
      {
        throw MsgpackEncodeError::make(
          Error::INVALID_EVENT_TIME,
          "time_point beyond 2106-02-07 06:28:15 UTC (seconds=" +
            std::to_string(secs_count) + ")");
      }

      // sub-second component in [0, 1s). since_epoch >= 0 was confirmed
      // above, so duration_cast (truncating toward zero) leaves a
      // non-negative remainder.
      const auto ns_count =
        std::chrono::duration_cast<std::chrono::nanoseconds>(
          since_epoch - secs)
          .count();
      return FluentdEventTime{
        static_cast<uint32_t>(secs_count), static_cast<uint32_t>(ns_count)};
    }

    [[nodiscard]] uint32_t seconds() const
    {
      return s_;
    }
    [[nodiscard]] uint32_t nanoseconds() const
    {
      return ns_;
    }

    bool operator==(const FluentdEventTime&) const = default;

  private:
    FluentdEventTime(uint32_t s, uint32_t ns) : s_(s), ns_(ns) {}
    uint32_t s_;
    uint32_t ns_;
  };

  // ===== Format byte constants =====
  // Named per the msgpack spec so the write_* bodies read as direct
  // transcriptions rather than magic numbers. Fix-family values are
  // prefixes that get OR'd with a small N.
  namespace fmt_byte
  {
    // Variable-length families.
    constexpr uint8_t NIL = 0xC0;
    constexpr uint8_t FALSE_ = 0xC2;
    constexpr uint8_t TRUE_ = 0xC3;
    constexpr uint8_t BIN_8 = 0xC4;
    constexpr uint8_t BIN_16 = 0xC5;
    constexpr uint8_t BIN_32 = 0xC6;
    constexpr uint8_t FLOAT_64 = 0xCB;
    constexpr uint8_t UINT_8 = 0xCC;
    constexpr uint8_t UINT_16 = 0xCD;
    constexpr uint8_t UINT_32 = 0xCE;
    constexpr uint8_t UINT_64 = 0xCF;
    constexpr uint8_t INT_8 = 0xD0;
    constexpr uint8_t INT_16 = 0xD1;
    constexpr uint8_t INT_32 = 0xD2;
    constexpr uint8_t INT_64 = 0xD3;
    constexpr uint8_t FIXEXT_8 = 0xD7;
    constexpr uint8_t STR_8 = 0xD9;
    constexpr uint8_t STR_16 = 0xDA;
    constexpr uint8_t STR_32 = 0xDB;
    constexpr uint8_t ARRAY_16 = 0xDC;
    constexpr uint8_t ARRAY_32 = 0xDD;
    constexpr uint8_t MAP_16 = 0xDE;

    // Fix-family prefixes (OR with the 4- or 5-bit count).
    constexpr uint8_t FIXSTR_PREFIX = 0xA0; // 0b101XXXXX (0xA0..0xBF)
    constexpr uint8_t FIXARRAY_PREFIX = 0x90; // 0b1001XXXX (0x90..0x9F)
    constexpr uint8_t FIXMAP_PREFIX = 0x80; // 0b1000XXXX (0x80..0x8F)
    // positive fixint: 0b0XXXXXXX (0x00..0x7F) — emitted as the value itself.
    // negative fixint: 0b111XXXXX (0xE0..0xFF) — emitted as the int8 bit
    // pattern.

    // Fluentd-specific ext type byte (NOT the msgpack-spec Timestamp's -1).
    constexpr uint8_t FLUENTD_EVENT_TIME_EXT_TYPE = 0x00;
  } // namespace fmt_byte

  // ===== Scalar encoders =====

  inline void write_nil(std::vector<uint8_t>& buf)
  {
    buf.push_back(fmt_byte::NIL);
  }

  inline void write_bool(std::vector<uint8_t>& buf, bool v)
  {
    buf.push_back(v ? fmt_byte::TRUE_ : fmt_byte::FALSE_);
  }

  // Smallest-format-wins:
  //   [0, 127]            -> positive fixint (1 byte)
  //   [128, 255]          -> uint 8           (2 bytes)
  //   [256, 65535]        -> uint 16          (3 bytes)
  //   [65536, 2^32-1]     -> uint 32          (5 bytes)
  //   [2^32, 2^64-1]      -> uint 64          (9 bytes)
  inline void write_uint(std::vector<uint8_t>& buf, uint64_t v)
  {
    if (v <= 0x7FU)
    {
      buf.push_back(static_cast<uint8_t>(v));
    }
    else if (v <= 0xFFU)
    {
      buf.push_back(fmt_byte::UINT_8);
      utils::write_be<uint8_t>(buf, static_cast<uint8_t>(v));
    }
    else if (v <= 0xFFFFU)
    {
      buf.push_back(fmt_byte::UINT_16);
      utils::write_be<uint16_t>(buf, static_cast<uint16_t>(v));
    }
    else if (v <= 0xFFFFFFFFU)
    {
      buf.push_back(fmt_byte::UINT_32);
      utils::write_be<uint32_t>(buf, static_cast<uint32_t>(v));
    }
    else
    {
      buf.push_back(fmt_byte::UINT_64);
      utils::write_be<uint64_t>(buf, v);
    }
  }

  // Smallest-format-wins for signed values.
  // For non-negative inputs we delegate to write_uint, so write_int(5)
  // produces one byte 0x05 (positive fixint), not the wider int 8 form
  // 0xD0 0x05. This is the spec's canonical form (smallest fitting
  // family across the unsigned and signed numeric ranges).
  //
  // For negative values:
  //   [-32, -1]                                -> negative fixint (1 byte)
  //   [-128, -33]                              -> int 8           (2 bytes)
  //   [-32768, -129]                           -> int 16          (3 bytes)
  //   [-2^31, -32769]                          -> int 32          (5 bytes)
  //   [INT64_MIN, -2^31 - 1]                   -> int 64          (9 bytes)
  inline void write_int(std::vector<uint8_t>& buf, int64_t v)
  {
    if (v >= 0)
    {
      write_uint(buf, static_cast<uint64_t>(v));
      return;
    }

    if (v >= -32)
    {
      // negative fixint: 0b111XXXXX, value is the 5-bit two's-complement.
      // Equivalently: byte = 0xE0 | (v & 0x1F), but the cleanest formulation
      // is to take the unsigned bit-pattern of the int8.
      buf.push_back(static_cast<uint8_t>(static_cast<int8_t>(v)));
    }
    else if (v >= std::numeric_limits<int8_t>::min())
    {
      buf.push_back(fmt_byte::INT_8);
      utils::write_be<uint8_t>(
        buf, static_cast<uint8_t>(static_cast<int8_t>(v)));
    }
    else if (v >= std::numeric_limits<int16_t>::min())
    {
      buf.push_back(fmt_byte::INT_16);
      utils::write_be<uint16_t>(
        buf, static_cast<uint16_t>(static_cast<int16_t>(v)));
    }
    else if (v >= std::numeric_limits<int32_t>::min())
    {
      buf.push_back(fmt_byte::INT_32);
      utils::write_be<uint32_t>(
        buf, static_cast<uint32_t>(static_cast<int32_t>(v)));
    }
    else
    {
      buf.push_back(fmt_byte::INT_64);
      utils::write_be<uint64_t>(buf, static_cast<uint64_t>(v));
    }
  }

  // Always emits float64 (0xCB ...). float32 narrowing is not
  // supported; callers wanting it can add a separate write_float32.
  //
  // NaN and infinity bit-patterns are passed through unchanged: the
  // function performs no canonicalisation. A signalling NaN stays a
  // signalling NaN; -inf stays -inf. If the caller needs canonical
  // NaN encoding, normalise before calling.
  inline void write_float(std::vector<uint8_t>& buf, double v)
  {
    static_assert(
      sizeof(double) == 8, "ccf::msgpack assumes IEEE-754 binary64 doubles");
    uint64_t bits = 0;
    std::memcpy(&bits, &v, sizeof(bits));
    buf.push_back(fmt_byte::FLOAT_64);
    utils::write_be<uint64_t>(buf, bits);
  }

  // ===== str =====
  //
  // Smallest-format-wins:
  //   [0, 31]               -> fixstr   (1-byte header)
  //   [32, 255]             -> str 8    (2-byte header)
  //   [256, 65535]          -> str 16   (3-byte header)
  //   [65536, 2^32-1]       -> str 32   (5-byte header)
  // Throws MsgpackEncodeError(STRING_TOO_LARGE) for sizes >= 2^32.
  //
  // The payload is copied verbatim — msgpack str is byte-array,
  // not text. We do not validate UTF-8 (the spec doesn't require it
  // and the wire format is opaque to byte content).
  inline void write_str(std::vector<uint8_t>& buf, std::string_view s)
  {
    // The reinterpret_cast below from `const char*` to `const uint8_t*`
    // is well-defined only if uint8_t IS unsigned char (so the access
    // is "an unsigned char or std::byte" per [basic.lval]). Hold this
    // invariant explicitly.
    static_assert(
      std::is_same_v<uint8_t, unsigned char>,
      "ccf::msgpack assumes uint8_t == unsigned char");

    const auto n = s.size();
    if (n <= 31U)
    {
      buf.push_back(static_cast<uint8_t>(fmt_byte::FIXSTR_PREFIX | n));
    }
    else if (n <= 0xFFU)
    {
      buf.push_back(fmt_byte::STR_8);
      utils::write_be<uint8_t>(buf, static_cast<uint8_t>(n));
    }
    else if (n <= 0xFFFFU)
    {
      buf.push_back(fmt_byte::STR_16);
      utils::write_be<uint16_t>(buf, static_cast<uint16_t>(n));
    }
    else if (n <= 0xFFFFFFFFULL)
    {
      buf.push_back(fmt_byte::STR_32);
      utils::write_be<uint32_t>(buf, static_cast<uint32_t>(n));
    }
    else
    {
      throw MsgpackEncodeError::make(
        Error::STRING_TOO_LARGE,
        "string length " + std::to_string(n) + " exceeds 2^32 - 1");
    }
    buf.insert(
      buf.end(),
      reinterpret_cast<const uint8_t*>(s.data()),
      reinterpret_cast<const uint8_t*>(s.data()) + n);
  }

  // ===== bin =====
  //
  // Smallest-format-wins:
  //   [0, 255]              -> bin 8    (2-byte header)
  //   [256, 65535]          -> bin 16   (3-byte header)
  //   [65536, 2^32-1]       -> bin 32   (5-byte header)
  // Throws MsgpackEncodeError(BIN_TOO_LARGE) for sizes >= 2^32.
  inline void write_bin(
    std::vector<uint8_t>& buf, std::span<const uint8_t> data)
  {
    const auto n = data.size();
    if (n <= 0xFFU)
    {
      buf.push_back(fmt_byte::BIN_8);
      utils::write_be<uint8_t>(buf, static_cast<uint8_t>(n));
    }
    else if (n <= 0xFFFFU)
    {
      buf.push_back(fmt_byte::BIN_16);
      utils::write_be<uint16_t>(buf, static_cast<uint16_t>(n));
    }
    else if (n <= 0xFFFFFFFFULL)
    {
      buf.push_back(fmt_byte::BIN_32);
      utils::write_be<uint32_t>(buf, static_cast<uint32_t>(n));
    }
    else
    {
      throw MsgpackEncodeError::make(
        Error::BIN_TOO_LARGE,
        "bin length " + std::to_string(n) + " exceeds 2^32 - 1");
    }
    buf.insert(buf.end(), data.begin(), data.end());
  }

  // ===== container headers =====
  //
  // Coupling: the wire format requires the element count up front, so
  // the caller must subsequently emit exactly `n` values (or `n`
  // key/value pairs for a map). A wrong `n` produces malformed msgpack
  // output silently — the encoder cannot check this at the header
  // call site.

  // Smallest-format-wins:
  //   [0, 15]              -> fixarray  (1-byte header)
  //   [16, 65535]          -> array_16  (3-byte header)
  //   [65536, 2^32-1]      -> array_32  (5-byte header)
  // Cannot throw MsgpackEncodeError: the input is uint32_t, so every
  // value fits one of the above families. (Contrast write_map_header,
  // which throws above 65535.)
  inline void write_array_header(std::vector<uint8_t>& buf, uint32_t n)
  {
    if (n <= 15U)
    {
      buf.push_back(static_cast<uint8_t>(fmt_byte::FIXARRAY_PREFIX | n));
    }
    else if (n <= 0xFFFFU)
    {
      buf.push_back(fmt_byte::ARRAY_16);
      utils::write_be<uint16_t>(buf, static_cast<uint16_t>(n));
    }
    else
    {
      buf.push_back(fmt_byte::ARRAY_32);
      utils::write_be<uint32_t>(buf, n);
    }
  }

  // Smallest-format-wins:
  //   [0, 15]              -> fixmap   (1-byte header)
  //   [16, 65535]          -> map_16   (3-byte header)
  // Throws MsgpackEncodeError(MAP_TOO_LARGE) for n > 65535. The
  // map_32 family is intentionally not supported — fluentd record
  // shapes never approach that key count, and rejecting at the
  // encoder boundary catches accidental over-large maps before they
  // become silent wire corruption. (Contrast write_array_header,
  // which supports the full uint32_t range via array_32.)
  inline void write_map_header(std::vector<uint8_t>& buf, uint32_t n)
  {
    if (n <= 15U)
    {
      buf.push_back(static_cast<uint8_t>(fmt_byte::FIXMAP_PREFIX | n));
    }
    else if (n <= 0xFFFFU)
    {
      buf.push_back(fmt_byte::MAP_16);
      utils::write_be<uint16_t>(buf, static_cast<uint16_t>(n));
    }
    else
    {
      throw MsgpackEncodeError::make(
        Error::MAP_TOO_LARGE,
        "map size " + std::to_string(n) +
          " exceeds map16 cap of 65535 keys (no map32 by design)");
    }
  }

  // ===== FluentdEventTime =====
  // Wire format (fluentd ext type 0, fixext8 form):
  //   0xD7 0x00 <s_be4> <ns_be4>.
  // The msgpack-spec Timestamp ext type (-1) has a different layout
  // and is intentionally NOT supported here.
  inline void write_event_time(std::vector<uint8_t>& buf, FluentdEventTime t)
  {
    buf.push_back(fmt_byte::FIXEXT_8);
    buf.push_back(fmt_byte::FLUENTD_EVENT_TIME_EXT_TYPE);
    utils::write_be<uint32_t>(buf, t.seconds());
    utils::write_be<uint32_t>(buf, t.nanoseconds());
  }
} // namespace ccf::msgpack
