// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Test-only helper: classify the first byte of a msgpack-encoded value
// into its format family. Used by smallest-format-wins property tests
// to assert the encoder picked the narrowest fitting form.
//
// The hex `case` labels here are intentional: they cross-check the
// `fmt_byte::*` constants used by the encoder by re-stating the same
// values from a separate source. A bug that swapped, say, 0xCD and
// 0xCE in either place is caught when the property tests run.

#include <cstdint>

namespace ccf::msgpack::test
{
  enum class FormatFamily : uint8_t
  {
    POSITIVE_FIXINT,
    NEGATIVE_FIXINT,
    FIXSTR,
    FIXARRAY,
    FIXMAP,
    NIL,
    FALSE_,
    TRUE_,
    BIN_8,
    BIN_16,
    BIN_32,
    FLOAT_64,
    UINT_8,
    UINT_16,
    UINT_32,
    UINT_64,
    INT_8,
    INT_16,
    INT_32,
    INT_64,
    FIXEXT_8,
    STR_8,
    STR_16,
    STR_32,
    ARRAY_16,
    ARRAY_32,
    MAP_16,
    NEVER_USED, // 0xC1, must never appear in valid encoded output
    UNRECOGNISED, // bytes the encoder cannot emit (ext families other
                  // than fixext8, the never-used 0xC1, etc.)
  };

  [[nodiscard]] inline FormatFamily classify_first_byte(uint8_t b)
  {
    // Fixed-prefix families first.
    if ((b & 0x80U) == 0x00U) // 0b0XXXXXXX
    {
      return FormatFamily::POSITIVE_FIXINT;
    }
    if ((b & 0xE0U) == 0xE0U) // 0b111XXXXX
    {
      return FormatFamily::NEGATIVE_FIXINT;
    }
    if ((b & 0xE0U) == 0xA0U) // 0b101XXXXX
    {
      return FormatFamily::FIXSTR;
    }
    if ((b & 0xF0U) == 0x90U) // 0b1001XXXX
    {
      return FormatFamily::FIXARRAY;
    }
    if ((b & 0xF0U) == 0x80U) // 0b1000XXXX
    {
      return FormatFamily::FIXMAP;
    }
    switch (b)
    {
      case 0xC0:
        return FormatFamily::NIL;
      case 0xC1:
        return FormatFamily::NEVER_USED;
      case 0xC2:
        return FormatFamily::FALSE_;
      case 0xC3:
        return FormatFamily::TRUE_;
      case 0xC4:
        return FormatFamily::BIN_8;
      case 0xC5:
        return FormatFamily::BIN_16;
      case 0xC6:
        return FormatFamily::BIN_32;
      case 0xCB:
        return FormatFamily::FLOAT_64;
      case 0xCC:
        return FormatFamily::UINT_8;
      case 0xCD:
        return FormatFamily::UINT_16;
      case 0xCE:
        return FormatFamily::UINT_32;
      case 0xCF:
        return FormatFamily::UINT_64;
      case 0xD0:
        return FormatFamily::INT_8;
      case 0xD1:
        return FormatFamily::INT_16;
      case 0xD2:
        return FormatFamily::INT_32;
      case 0xD3:
        return FormatFamily::INT_64;
      case 0xD7:
        return FormatFamily::FIXEXT_8;
      case 0xD9:
        return FormatFamily::STR_8;
      case 0xDA:
        return FormatFamily::STR_16;
      case 0xDB:
        return FormatFamily::STR_32;
      case 0xDC:
        return FormatFamily::ARRAY_16;
      case 0xDD:
        return FormatFamily::ARRAY_32;
      case 0xDE:
        return FormatFamily::MAP_16;
      default:
        return FormatFamily::UNRECOGNISED;
    }
  }
} // namespace ccf::msgpack::test
