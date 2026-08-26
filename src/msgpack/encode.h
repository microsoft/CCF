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
//   - Arrays (fixarray/array16/array32) and maps (fixmap/map16/map32).
// Out of scope:
//   - float32 (write_float always emits float64).
//
// Failure modes that may escape ANY write_* function:
//   - MsgpackEncodeError on encoder-defined limits (see Error enum).
//   - std::bad_alloc from the underlying std::vector if buffer growth
//     fails. The encoder offers no special handling - callers that
//     might recover from OOM should treat the buffer as undefined-but-
//     well-typed.

#include "msgpack/endian.h"

#include <cstdint>
#include <cstring>
#include <functional>
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
    INVALID_EVENT_TIME = 4, // outside Fluentd EventTime's representable range
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
      case Error::INVALID_EVENT_TIME:
        return "INVALID_EVENT_TIME";
      default:
        return "UNKNOWN_MSGPACK_ERROR";
    }
  }

  // Thrown by encoder boundary functions.
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
    [[nodiscard]] static MsgpackEncodeError make(
      Error err, std::string_view detail)
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
    constexpr uint8_t MAP_32 = 0xDF;

    // Fix-family prefixes (OR with the 4- or 5-bit count).
    constexpr uint8_t FIXSTR_PREFIX = 0xA0; // 0b101XXXXX (0xA0..0xBF)
    constexpr uint8_t FIXARRAY_PREFIX = 0x90; // 0b1001XXXX (0x90..0x9F)
    constexpr uint8_t FIXMAP_PREFIX = 0x80; // 0b1000XXXX (0x80..0x8F)
    // positive fixint: 0b0XXXXXXX (0x00..0x7F) - emitted as the value itself.
    // negative fixint: 0b111XXXXX (0xE0..0xFF) - emitted as the int8 bit
    // pattern.

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
  // The payload is copied verbatim. The msgpack spec defines str as
  // UTF-8, but this encoder does not validate it.
  inline void write_str(std::vector<uint8_t>& buf, std::string_view s)
  {
    // The reinterpret_cast below from `const char*` to `const uint8_t*`
    // is well-defined only if uint8_t IS unsigned char (so the access
    // is "an unsigned char or std::byte" per [basic.lval]). Hold this
    // invariant explicitly.
    static_assert(
      std::is_same_v<uint8_t, unsigned char>,
      "ccf::msgpack assumes uint8_t == unsigned char");

    std::string aliased_s;
    if (!buf.empty() && !s.empty())
    {
      const auto less = std::less<const uint8_t*>{};
      const auto* const buf_begin = buf.data();
      const auto* const buf_end = buf_begin + buf.size();
      const auto* const s_begin = reinterpret_cast<const uint8_t*>(s.data());
      const auto* const s_end = s_begin + s.size();
      if (less(s_begin, buf_end) && less(buf_begin, s_end))
      {
        aliased_s.assign(s);
        s = aliased_s;
      }
    }

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
    std::vector<uint8_t> aliased_data;
    if (!buf.empty() && !data.empty())
    {
      const auto less = std::less<const uint8_t*>{};
      const auto* const buf_begin = buf.data();
      const auto* const buf_end = buf_begin + buf.size();
      const auto* const data_begin = data.data();
      const auto* const data_end = data_begin + data.size();
      if (less(data_begin, buf_end) && less(buf_begin, data_end))
      {
        aliased_data.assign(data.begin(), data.end());
        data = aliased_data;
      }
    }

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
  // output silently - the encoder cannot check this at the header
  // call site.

  // Smallest-format-wins:
  //   [0, 15]              -> fixarray  (1-byte header)
  //   [16, 65535]          -> array_16  (3-byte header)
  //   [65536, 2^32-1]      -> array_32  (5-byte header)
  // Cannot throw MsgpackEncodeError: the input is uint32_t, so every
  // value fits one of the above families.
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
  //   [65536, 2^32-1]      -> map_32   (5-byte header)
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
      buf.push_back(fmt_byte::MAP_32);
      utils::write_be<uint32_t>(buf, n);
    }
  }
} // namespace ccf::msgpack
